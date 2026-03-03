# file: main.py
# GCP Cloud Run Security Agent — CLI entry point
# Pipeline: resolve → scan (Cloud Run + Cloud Functions) → traffic → classify → remediate → report
#
# Project ID separation:
# - --project / --folder / --org  = scan target (what to scan)
# - --vertex-project or PROJECT_ID in .env = Vertex AI auth (who pays for Gemini)
#
# Report output strategy:
# - --project  → per-project HTML report only (no org summary)
# - --folder   → per-project HTML (Medium+ only) + folder summary dashboard HTML
# - --org      → per-project HTML (Medium+ only) + org summary dashboard HTML
#
# API call optimisation:
# - project_resolver.py fetches project_id + project_number in ONE call
# - traffic_analyzer.py uses batch query — 1 Cloud Logging call per project regardless of service count
# - All scanning steps run in parallel across projects using ThreadPoolExecutor

import argparse
import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from config import settings
from tools.project_resolver import resolve_projects
from tools.cloud_run_scanner import scan_cloud_run_services
from tools.cloud_functions_scanner import scan_cloud_functions
from tools.risk_classifier import classify_service, summarise_findings
from tools.remediation_templates import get_remediation
from tools.cost_estimator import estimate_scan, print_dry_run_summary
from agent.orchestrator import generate_and_save_reports

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="GCP Security Agent — Cloud Run + Cloud Functions Exposure Scanner"
    )

    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--project", type=str, help="Single GCP project ID to scan")
    scope.add_argument("--folder",  type=str, help="GCP folder ID — scans all projects under it")
    scope.add_argument("--org",     type=str, help="GCP org ID — scans all projects in the org")

    parser.add_argument(
        "--resource",
        type=str,
        choices=["all", "cloud-run", "cloud-functions"],
        default="all",
        help="Resource types to scan. Default: all (Cloud Run Services + Cloud Functions Gen1/Gen2)",
    )
    parser.add_argument(
        "--vertex-project",
        type=str,
        default=None,
        help=(
            "GCP project ID to use for Vertex AI / Gemini auth. "
            "Defaults to PROJECT_ID in .env. "
            "Use when scanning a project you do not have roles/aiplatform.user on."
        ),
    )
    parser.add_argument(
        "--prompt",
        type=str,
        required=False,
        default="Analyze Cloud Run and Cloud Functions public exposure and generate remediation report",
        help="Natural language prompt — used as Gemini report context.",
    )
    parser.add_argument("--dry-run",      action="store_true", help="Estimate scope without running the full scan")
    parser.add_argument("--max-projects", type=int, default=settings.MAX_PROJECTS, help="Cap number of projects to scan")
    return parser.parse_args()


def print_findings_table(findings: list[dict]):
    """Prints dynamically aligned findings table to terminal."""
    if not findings:
        return
    headers = ["PROJECT", "RESOURCE", "TYPE", "REGION", "INGRESS", "UNAUTH?", "REQUESTS", "RISK LEVEL", "CATEGORY"]
    rows = [[
        f.get("project_id", ""),
        f.get("name", ""),
        _short_type(f.get("resource_type", "cloud_run_service")),
        f.get("region", ""),
        f.get("ingress", ""),
        "YES" if f.get("unauthenticated") else "NO",
        str(f.get("request_count", "N/A")),
        f.get("risk_level", ""),
        f.get("risk_category", ""),
    ] for f in findings]
    col_widths = [max(len(h), max((len(r[i]) for r in rows), default=0)) for i, h in enumerate(headers)]
    def fmt(row): return " | ".join(cell.ljust(col_widths[i]) for i, cell in enumerate(row))
    print(fmt(headers))
    print("-" * (sum(col_widths) + 3 * (len(headers) - 1)))
    for row in rows:
        print(fmt(row))


def _short_type(resource_type: str) -> str:
    return {
        "cloud_run_service":   "CR Service",
        "cloud_function_gen1": "CF Gen1 ⚠️",
        "cloud_function_gen2": "CF Gen2",
    }.get(resource_type, resource_type)


def fetch_traffic_for_project(pid: str, project_findings: list) -> list:
    """
    ONE Cloud Logging batch query per project regardless of service count.
    Quota-safe at org scale: 1500 projects = 1500 total logging calls.
    """
    from tools.traffic_analyzer import analyze_traffic_batch
    return analyze_traffic_batch(
        project_id=pid,
        findings=project_findings,
        lookback_days=settings.TRAFFIC_LOOKBACK_DAYS,
    )


def scan_project(p: dict, scan_resource: str) -> tuple[list, list]:
    """Scans a single project. Returns (cr_findings, cf_findings)."""
    pid  = p["project_id"]
    pnum = p["project_number"]
    cr_findings = scan_cloud_run_services(pid, pnum)   if scan_resource in ("all", "cloud-run")        else []
    cf_findings = scan_cloud_functions(pid, pnum)      if scan_resource in ("all", "cloud-functions")  else []
    return cr_findings, cf_findings


def main():
    args = parse_args()

    vertex_project = args.vertex_project or settings.PROJECT_ID
    if not vertex_project:
        raise ValueError(
            "Vertex AI project required.\n"
            "Set PROJECT_ID in .env or pass --vertex-project YOUR_PROJECT_ID"
        )

    # --- Scope type drives report output strategy ---
    if args.project:
        scope_type    = "project"
        project_scope = f"project:{args.project}"
    elif args.folder:
        scope_type    = "folder"
        project_scope = f"folder:{args.folder}"
    elif args.org:
        scope_type    = "org"
        project_scope = f"org:{args.org}"
    else:
        scope_type    = "project"
        project_scope = f"project:{vertex_project}"

    report_mode = (
        "per-project HTML only"
        if scope_type == "project"
        else f"per-project HTML (Medium+) + {scope_type} summary dashboard"
    )

    print(f"Agent initialized | Scope: {project_scope} | Prompt: {args.prompt}")
    print(f"LLM: {settings.GEMINI_MODEL} @ {settings.VERTEX_AI_LOCATION} (project: {vertex_project})")
    print(f"Resources: { {'all':'Cloud Run + Cloud Functions (Gen1+Gen2)','cloud-run':'Cloud Run only','cloud-functions':'Cloud Functions only'}[args.resource] }")
    print(f"Traffic lookback: {settings.TRAFFIC_LOOKBACK_DAYS} days")
    print(f"Report mode: {report_mode}")
    print("---")

    # Step 1: Resolve projects
    scan_project_id = args.project or (None if args.folder or args.org else vertex_project)
    projects = resolve_projects(project_id=scan_project_id, folder_id=args.folder, org_id=args.org)
    print(f"Resolved {len(projects)} project(s) to scan")

    if args.max_projects and len(projects) > args.max_projects:
        print(f"Warning: capped to {args.max_projects} of {len(projects)} resolved projects")
        projects = projects[:args.max_projects]

    # Step 2: Parallel scan
    print(f"\nScanning {len(projects)} project(s)...")
    all_cr_findings, all_cf_findings = [], []

    with ThreadPoolExecutor(max_workers=settings.MAX_WORKERS) as executor:
        futures = {executor.submit(scan_project, p, args.resource): p for p in projects}
        for i, future in enumerate(as_completed(futures), 1):
            p = futures[future]
            pid = p["project_id"]
            try:
                cr, cf = future.result()
                for f in cr: f["project_id"] = pid; f.setdefault("resource_type", "cloud_run_service")
                for f in cf: f["project_id"] = pid
                gen1 = sum(1 for f in cf if f.get("resource_type") == "cloud_function_gen1")
                gen2 = sum(1 for f in cf if f.get("resource_type") == "cloud_function_gen2")
                status = f"CR:{len(cr)}" + (f" | CF Gen1:{gen1} Gen2:{gen2}" if args.resource in ("all","cloud-functions") else "")
                print(f"✓ {pid} — {len(cr)+len(cf)} finding(s) [{status}] ({i}/{len(projects)})")
                all_cr_findings.extend(cr)
                all_cf_findings.extend(cf)
            except Exception as e:
                print(f"✗ Failed: {pid} — {e}")

    all_findings = all_cr_findings + all_cf_findings

    # Step 3: Dry-run gate
    if args.dry_run:
        print_dry_run_summary(estimate_scan([p["project_id"] for p in projects], all_findings))
        if input("\nProceed with full scan? [y/N]: ").strip().lower() != "y":
            print("Dry run complete. No changes made.")
            return

    # Step 4: Traffic analysis — 1 batch query per project
    findings_by_project: dict = defaultdict(list)
    for f in all_findings:
        findings_by_project[f["project_id"]].append(f)

    print(f"\nAnalyzing traffic — 1 batch query per project ({len(findings_by_project)} projects)...")
    with ThreadPoolExecutor(max_workers=settings.MAX_WORKERS) as executor:
        futures = {executor.submit(fetch_traffic_for_project, pid, pf): pid for pid, pf in findings_by_project.items()}
        for future in as_completed(futures):
            pid = futures[future]
            try:
                for f in future.result():
                    print(f"✓ [{_short_type(f.get('resource_type','cloud_run_service'))}] {f['name']} — {f.get('request_count',0)} req | {f.get('classification','Unknown')}")
            except Exception as e:
                print(f"✗ Traffic batch failed: {pid} — {e}")

    # Step 5: Risk classification (deterministic, zero LLM)
    print("\nClassifying risk levels...")
    classified = [classify_service(f) for f in all_findings]

    # Step 6: Remediation commands (deterministic, zero LLM)
    for f in classified:
        f["remediation"] = get_remediation(f)

    # Step 7: Print terminal table
    print()
    if not classified:
        print(f"No public services or functions found in scope: {project_scope}")
        return
    print_findings_table(classified)

    # Step 8: Summary counts
    summary    = summarise_findings(classified)
    gen1_total = sum(1 for f in classified if f.get("resource_type") == "cloud_function_gen1")
    print(
        f"\nScan complete | {summary['total']} finding(s) | "
        f"Critical: {summary['Critical']} | High: {summary['High']} | "
        f"Medium: {summary['Medium']} | Needs remediation: {summary['needs_remediation']}"
        + (f" | Gen1 (migration required): {gen1_total}" if gen1_total else "")
    )

    # Step 9: Single Gemini call → HTML report generation
    # scope_type controls which files are created:
    #   "project" → report_<pid>_<ts>.html only
    #   "folder"  → report_<pid>_<ts>.html per Medium+ project + summary_folder_<ts>.html
    #   "org"     → report_<pid>_<ts>.html per Medium+ project + summary_org_<ts>.html
    print(f"\nGenerating HTML report(s) with {settings.GEMINI_MODEL}...")

    result = generate_and_save_reports(
        classified_findings=classified,
        summary=summary,
        project_scope=project_scope,
        scope_type=scope_type,
        user_prompt=args.prompt,
        vertex_project=vertex_project,
        scan_date=datetime.now().strftime("%Y-%m-%d"),
    )

    print()
    for rpath in result["project_reports"]:
        print(f"  📄 Project report    : {rpath}")
    if result["summary_report"]:
        print(f"  📊 Summary dashboard : {result['summary_report']}")

    print("\nDone.")


if __name__ == "__main__":
    main()
