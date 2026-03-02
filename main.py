# file: main.py
# GCP Cloud Run Security Agent — CLI entry point
# Pipeline: resolve → scan → traffic → classify → remediate → report
#
# Project ID separation:
# - --project / --folder / --org  = scan target (what to scan)
# - --vertex-project or PROJECT_ID in .env = Vertex AI auth (who pays for Gemini)
# These are intentionally independent — you can scan any project you have read
# access to, as long as you have roles/aiplatform.user on your Vertex AI project.
#
# API call optimisation:
# - project_resolver.py fetches project_id + project_number in ONE call
# - cloud_run_scanner.py receives project_number directly — no extra get_project call
# - traffic_analyzer.py runs in parallel — 10x faster for multi-service projects

import argparse
import logging
from config import settings
from tools.project_resolver import resolve_projects
from tools.cloud_run_scanner import scan_cloud_run_services
from tools.traffic_analyzer import analyze_traffic
from tools.risk_classifier import classify_service, summarise_findings
from tools.remediation_templates import get_remediation
from tools.cost_estimator import estimate_scan, print_dry_run_summary
from agent.orchestrator import generate_report, save_report
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="GCP Security Agent — Cloud Run Public Exposure Scanner"
    )

    # --- Scan scope (what to scan) ---
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--project", type=str, help="Single GCP project ID to scan")
    scope.add_argument("--folder", type=str, help="GCP folder ID — scans all projects under it")
    scope.add_argument("--org", type=str, help="GCP org ID — scans all projects in the org")

    # --- Vertex AI auth (who pays for Gemini) ---
    parser.add_argument(
        "--vertex-project",
        type=str,
        default=None,
        help=(
            "GCP project ID to use for Vertex AI / Gemini auth. "
            "Defaults to PROJECT_ID in .env. "
            "Use this when scanning a project you do not have roles/aiplatform.user on. "
            "Example: --vertex-project my-personal-project --project company-project"
        )
    )

    parser.add_argument(
        "--prompt",
        type=str,
        required=False,
        default="Analyze Cloud Run public exposure and generate remediation report",
        help="Natural language prompt. Used as Gemini report context. "
             "Prompt-based filtering coming in Phase 5."
    )
    parser.add_argument("--dry-run", action="store_true", help="Estimate scope without running LLM")
    parser.add_argument("--max-projects", type=int, default=settings.MAX_PROJECTS, help="Cap number of projects to scan")
    return parser.parse_args()


def print_findings_table(findings: list[dict]):
    """Prints dynamically aligned findings table to terminal."""
    if not findings:
        return

    headers = ["PROJECT", "SERVICE", "REGION", "INGRESS", "UNAUTH?", "REQUESTS", "RISK LEVEL", "CATEGORY"]
    rows = [
        [
            f.get("project_id", ""),
            f.get("name", ""),
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


def fetch_traffic(finding: dict) -> tuple:
    """Worker function for parallel traffic analysis."""
    traffic = analyze_traffic(
        project_id=finding["project_id"],
        service_name=finding["name"],
        region=finding["region"],
        lookback_days=settings.TRAFFIC_LOOKBACK_DAYS,
    )
    return finding, traffic


def main():
    args = parse_args()

    # --- Vertex AI project (for Gemini auth) ---
    # Priority: --vertex-project flag > PROJECT_ID in .env
    # This is NEVER the scan target — it is only used to authenticate Gemini calls.
    vertex_project = args.vertex_project or settings.PROJECT_ID
    if not vertex_project:
        raise ValueError(
            "Vertex AI project required for Gemini report generation.\n"
            "Set PROJECT_ID in .env or pass --vertex-project YOUR_PROJECT_ID"
        )

    # --- Scan scope ---
    if args.project:
        project_scope = f"project:{args.project}"
    elif args.folder:
        project_scope = f"folder:{args.folder}"
    elif args.org:
        project_scope = f"org:{args.org}"
    else:
        project_scope = f"project:{vertex_project}"

    print(f"Agent initialized | Scope: {project_scope} | Prompt: {args.prompt}")
    print(f"LLM: {settings.GEMINI_MODEL} @ {settings.VERTEX_AI_LOCATION} (project: {vertex_project})")
    print(f"Traffic lookback: {settings.TRAFFIC_LOOKBACK_DAYS} days")
    print("---")

    # Step 1: Resolve projects
    # Returns list of dicts: [{project_id, project_number}, ...]
    # Uses scan scope — NOT vertex_project
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

    # Step 3: Parallel Cloud Run scan
    print(f"\nScanning {len(projects)} project(s) for public Cloud Run services...")
    all_findings = []

    with ThreadPoolExecutor(max_workers=settings.MAX_WORKERS) as executor:
        futures = {
            executor.submit(
                scan_cloud_run_services,
                p["project_id"],
                p["project_number"],
            ): p
            for p in projects
        }
        for i, future in enumerate(as_completed(futures), 1):
            p = futures[future]
            pid = p["project_id"]
            try:
                findings = future.result()
                print(f"✓ Scanned: {pid} — {len(findings)} public service(s) found ({i}/{len(projects)})")
                for f in findings:
                    f["project_id"] = pid
                all_findings.extend(findings)
            except Exception as e:
                print(f"✗ Failed: {pid} — {e}")

    # Step 4: Dry-run gate
    project_ids = [p["project_id"] for p in projects]
    estimate = estimate_scan(project_ids, all_findings)
    if args.dry_run:
        print_dry_run_summary(estimate)
        confirm = input("\nProceed with full scan? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Dry run complete. No changes made.")
            return

    # Step 5: Traffic analysis — parallel
    print(f"\nAnalyzing traffic for {len(all_findings)} public service(s)...")

    with ThreadPoolExecutor(max_workers=settings.MAX_WORKERS) as executor:
        futures = {executor.submit(fetch_traffic, f): f for f in all_findings}
        for future in as_completed(futures):
            try:
                finding, traffic = future.result()
                finding.update(traffic)
                print(f"✓ {finding['name']} — {finding.get('request_count', 0)} requests | {finding.get('classification', 'Unknown')}")
            except Exception as e:
                print(f"✗ Traffic fetch failed — {e}")

    # Step 6: Deterministic risk classification — zero LLM cost
    print("\nClassifying risk levels...")
    classified = [classify_service(f) for f in all_findings]

    # Step 7: Generate remediation commands — zero LLM cost
    for finding in classified:
        finding["remediation"] = get_remediation(finding)

    # Step 8: Print findings table
    print()
    if classified:
        print_findings_table(classified)
    else:
        print(f"No public Cloud Run services found in scope: {project_scope}")
        return

    # Step 9: Summary counts
    summary = summarise_findings(classified)
    print(f"\nScan complete | {summary['total']} public service(s) | "
          f"Critical: {summary['Critical']} | High: {summary['High']} | "
          f"Medium: {summary['Medium']} | Needs remediation: {summary['needs_remediation']}")

    # Step 10: Single Gemini call — uses vertex_project for auth, not scan target
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
