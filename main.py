# file: main.py
# GCP Cloud Run Security Agent — CLI entry point
# Pipeline: resolve → scan (Cloud Run + Cloud Functions) → traffic → classify → remediate → report
#
# Project ID separation:
# - --project / --folder / --org  = scan target (what to scan)
# - --vertex-project or PROJECT_ID in .env = Vertex AI auth (who pays for Gemini)
#
# API call optimisation:
# - project_resolver.py fetches project_id + project_number in ONE call
# - cloud_run_scanner.py receives project_number directly — no extra get_project call
# - cloud_functions_scanner.py receives project_number directly — no extra get_project call
# - traffic_analyzer.py runs in parallel — fast for multi-service projects
# - All scanning steps run in parallel across projects using ThreadPoolExecutor

import argparse
import logging
from config import settings
from tools.project_resolver import resolve_projects
from tools.cloud_run_scanner import scan_cloud_run_services
from tools.cloud_functions_scanner import scan_cloud_functions
from tools.risk_classifier import classify_service, summarise_findings
from tools.remediation_templates import get_remediation
from tools.cost_estimator import estimate_scan, print_dry_run_summary
from agent.orchestrator import generate_report, save_report
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="GCP Security Agent — Cloud Run + Cloud Functions Exposure Scanner"
    )

    # --- Scan scope ---
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--project", type=str, help="Single GCP project ID to scan")
    scope.add_argument("--folder", type=str, help="GCP folder ID — scans all projects under it")
    scope.add_argument("--org", type=str, help="GCP org ID — scans all projects in the org")

    # --- Resource type filter ---
    parser.add_argument(
        "--resource",
        type=str,
        choices=["all", "cloud-run", "cloud-functions"],
        default="all",
        help="Resource types to scan. Default: all (Cloud Run Services + Cloud Functions Gen1/Gen2)"
    )

    # --- Vertex AI auth ---
    parser.add_argument(
        "--vertex-project",
        type=str,
        default=None,
        help=(
            "GCP project ID to use for Vertex AI / Gemini auth. "
            "Defaults to PROJECT_ID in .env. "
            "Use when scanning a project you do not have roles/aiplatform.user on."
        )
    )

    parser.add_argument(
        "--prompt",
        type=str,
        required=False,
        default="Analyze Cloud Run and Cloud Functions public exposure and generate remediation report",
        help="Natural language prompt. Used as Gemini report context. "
             "Prompt-based filtering coming in Phase 5."
    )
    parser.add_argument("--dry-run", action="store_true", help="Estimate scope without running the full scan")
    parser.add_argument("--max-projects", type=int, default=settings.MAX_PROJECTS, help="Cap number of projects to scan")
    return parser.parse_args()


def print_findings_table(findings: list[dict]):
    """Prints dynamically aligned findings table to terminal."""
    if not findings:
        return

    headers = ["PROJECT", "RESOURCE", "TYPE", "REGION", "INGRESS", "UNAUTH?", "REQUESTS", "RISK LEVEL", "CATEGORY"]
    rows = [
        [
            f.get("project_id", ""),
            f.get("name", ""),
            _short_type(f.get("resource_type", "cloud_run_service")),
            f.get("region", ""),
            f.get("ingress", ""),
            "YES" if f.get("unauthenticated") else "NO",
            str(f.get("request_count", "N/A")),
            f.get("risk_level", ""),
            f.get("risk_category", ""),
        ]
        for f in findings
    ]

    col_widths = [
        max(len(h), max((len(r[i]) for r in rows), default=0))
        for i, h in enumerate(headers)
    ]

    def format_row(row):
        return " | ".join(cell.ljust(col_widths[i]) for i, cell in enumerate(row))

    separator = "-" * (sum(col_widths) + 3 * (len(headers) - 1))
    print(format_row(headers))
    print(separator)
    for row in rows:
        print(format_row(row))


def _short_type(resource_type: str) -> str:
    """Returns a short display label for resource type."""
    return {
        "cloud_run_service":    "CR Service",
        "cloud_function_gen1":  "CF Gen1 ⚠️",
        "cloud_function_gen2":  "CF Gen2",
    }.get(resource_type, resource_type)


def fetch_traffic_for_project(pid: str, project_findings: list) -> list:
    """
    Worker function — fetches traffic for ALL findings in a project
    in a SINGLE Cloud Logging API call (batch query).

    Why: Cloud Logging quota is 60 read requests/min PER PROJECT being read.
    Firing 1 call per service (old approach) easily exceeds this on projects
    with many public services. Batch = 1 call per project = quota safe
    at any scale, with zero impact on production traffic patterns.

    1 project  = 1 API call regardless of service count.
    1500 projects = 1500 total logging calls across the org.
    """
    from tools.traffic_analyzer import analyze_traffic_batch
    return analyze_traffic_batch(
        project_id=pid,
        findings=project_findings,
        lookback_days=settings.TRAFFIC_LOOKBACK_DAYS,
    )


def scan_project(p: dict, scan_resource: str) -> tuple[list, list]:
    """
    Scans a single project for Cloud Run Services and/or Cloud Functions.
    Returns (cloud_run_findings, cloud_functions_findings).
    """
    pid = p["project_id"]
    pnum = p["project_number"]

    cr_findings = []
    cf_findings = []

    if scan_resource in ("all", "cloud-run"):
        cr_findings = scan_cloud_run_services(pid, pnum)

    if scan_resource in ("all", "cloud-functions"):
        cf_findings = scan_cloud_functions(pid, pnum)

    return cr_findings, cf_findings


def main():
    args = parse_args()

    # --- Vertex AI project (Gemini auth) ---
    vertex_project = args.vertex_project or settings.PROJECT_ID
    if not vertex_project:
        raise ValueError(
            "Vertex AI project required for Gemini report generation.\n"
            "Set PROJECT_ID in .env or pass --vertex-project YOUR_PROJECT_ID"
        )

    # --- Scan scope label ---
    if args.project:
        project_scope = f"project:{args.project}"
    elif args.folder:
        project_scope = f"folder:{args.folder}"
    elif args.org:
        project_scope = f"org:{args.org}"
    else:
        project_scope = f"project:{vertex_project}"

    resource_label = {
        "all": "Cloud Run Services + Cloud Functions (Gen1 + Gen2)",
        "cloud-run": "Cloud Run Services only",
        "cloud-functions": "Cloud Functions only (Gen1 + Gen2)",
    }[args.resource]

    print(f"Agent initialized | Scope: {project_scope} | Prompt: {args.prompt}")
    print(f"LLM: {settings.GEMINI_MODEL} @ {settings.VERTEX_AI_LOCATION} (project: {vertex_project})")
    print(f"Resources: {resource_label}")
    print(f"Traffic lookback: {settings.TRAFFIC_LOOKBACK_DAYS} days")
    print("---")

    # Step 1: Resolve projects
    scan_project_id = args.project or (None if args.folder or args.org else vertex_project)
    projects = resolve_projects(
        project_id=scan_project_id,
        folder_id=args.folder,
        org_id=args.org,
    )
    print(f"Resolved {len(projects)} project(s) to scan")

    # Step 2: Apply project cap
    if args.max_projects and len(projects) > args.max_projects:
        print(f"Warning: capped to {args.max_projects} of {len(projects)} resolved projects")
        projects = projects[:args.max_projects]

    # Step 3: Parallel scan — Cloud Run + Cloud Functions per project
    print(f"\nScanning {len(projects)} project(s)...")
    all_cr_findings = []
    all_cf_findings = []

    with ThreadPoolExecutor(max_workers=settings.MAX_WORKERS) as executor:
        futures = {
            executor.submit(scan_project, p, args.resource): p
            for p in projects
        }
        for i, future in enumerate(as_completed(futures), 1):
            p = futures[future]
            pid = p["project_id"]
            try:
                cr_findings, cf_findings = future.result()

                for f in cr_findings:
                    f["project_id"] = pid
                    f.setdefault("resource_type", "cloud_run_service")
                for f in cf_findings:
                    f["project_id"] = pid

                total = len(cr_findings) + len(cf_findings)
                gen1_count = sum(1 for f in cf_findings if f.get("resource_type") == "cloud_function_gen1")
                gen2_count = sum(1 for f in cf_findings if f.get("resource_type") == "cloud_function_gen2")

                status = f"CR:{len(cr_findings)}"
                if args.resource in ("all", "cloud-functions"):
                    status += f" | CF Gen1:{gen1_count} Gen2:{gen2_count}"
                print(f"✓ Scanned: {pid} — {total} finding(s) [{status}] ({i}/{len(projects)})")

                all_cr_findings.extend(cr_findings)
                all_cf_findings.extend(cf_findings)

            except Exception as e:
                print(f"✗ Failed: {pid} — {e}")

    all_findings = all_cr_findings + all_cf_findings

    # Step 4: Dry-run gate
    project_ids = [p["project_id"] for p in projects]
    estimate = estimate_scan(project_ids, all_findings)
    if args.dry_run:
        print_dry_run_summary(estimate)
        confirm = input("\nProceed with full scan? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Dry run complete. No changes made.")
            return

    # Step 5: Traffic analysis — 1 batch API call per project (quota safe)
    # Groups findings by project, then fires ONE Cloud Logging query per project.
    #
    # Old approach: N services × 1 call = N calls per project → hits 60 req/min quota
    # New approach: N services × 0 calls + 1 batch call = 1 call per project → safe
    # Impact at org scale: 1500 projects = 1500 total logging calls (was 15,000+)
    # Zero changes to scanned projects — single passive read only.
    from collections import defaultdict
    findings_by_project: dict = defaultdict(list)
    for f in all_findings:
        findings_by_project[f["project_id"]].append(f)

    print(f"\nAnalyzing traffic for {len(all_findings)} finding(s) — 1 batch query per project ({len(findings_by_project)} projects)...")
    with ThreadPoolExecutor(max_workers=settings.MAX_WORKERS) as executor:
        futures = {
            executor.submit(fetch_traffic_for_project, pid, pfindings): pid
            for pid, pfindings in findings_by_project.items()
        }
        for future in as_completed(futures):
            pid = futures[future]
            try:
                enriched = future.result()
                for f in enriched:
                    rtype = _short_type(f.get("resource_type", "cloud_run_service"))
                    print(f"✓ [{rtype}] {f['name']} — {f.get('request_count', 0)} requests | {f.get('classification', 'Unknown')}")
            except Exception as e:
                print(f"✗ Traffic batch failed for {pid} — {e}")

    # Step 6: Deterministic risk classification — zero LLM cost
    print("\nClassifying risk levels...")
    classified = [classify_service(f) for f in all_findings]

    # Step 7: Generate remediation commands — zero LLM cost
    # Routes to Cloud Run or Cloud Functions templates automatically
    for finding in classified:
        finding["remediation"] = get_remediation(finding)

    # Step 8: Print findings table
    print()
    if classified:
        print_findings_table(classified)
    else:
        print(f"No public services or functions found in scope: {project_scope}")
        return

    # Step 9: Summary counts
    summary = summarise_findings(classified)
    gen1_total = sum(1 for f in classified if f.get("resource_type") == "cloud_function_gen1")
    gen1_line = f" | Gen1 functions (migration required): {gen1_total}" if gen1_total > 0 else ""

    print(f"\nScan complete | {summary['total']} finding(s) | "
          f"Critical: {summary['Critical']} | High: {summary['High']} | "
          f"Medium: {summary['Medium']} | Needs remediation: {summary['needs_remediation']}"
          f"{gen1_line}")

    # Step 10: Single Gemini call — report synthesis only
    print(f"\nGenerating security report with {settings.GEMINI_MODEL}...")
    report = generate_report(
        classified_findings=classified,
        summary=summary,
        project_scope=project_scope,
        user_prompt=args.prompt,
        project_id=vertex_project,
    )
    report_path = save_report(report, project_scope)
    print(f"Report saved to: {report_path}")


if __name__ == "__main__":
    main()
