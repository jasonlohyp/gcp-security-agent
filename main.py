# file: main.py
# GCP Cloud Run Security Agent — CLI entry point
# Pipeline: resolve → scan → traffic → classify → remediate → report

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
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--project", type=str, help="Single GCP project ID")
    scope.add_argument("--folder", type=str, help="GCP folder ID — scans all projects under it")
    scope.add_argument("--org", type=str, help="GCP org ID — scans all projects in the org")

    parser.add_argument("--prompt", type=str, required=True, help="Natural language prompt")
    parser.add_argument("--dry-run", action="store_true", help="Estimate scope and cost without running LLM")
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


def main():
    args = parse_args()

    # Resolve primary project for Vertex AI auth
    primary_project = args.project or settings.PROJECT_ID
    if not primary_project:
        raise ValueError("Project ID required for Vertex AI. Pass --project or set PROJECT_ID in .env")

    # Determine scope label
    if args.project:
        project_scope = f"project:{args.project}"
    elif args.folder:
        project_scope = f"folder:{args.folder}"
    elif args.org:
        project_scope = f"org:{args.org}"
    else:
        project_scope = f"project:{primary_project}"

    print(f"Agent initialized | Scope: {project_scope} | Prompt: {args.prompt}")
    print(f"LLM: {settings.GEMINI_MODEL} @ {settings.VERTEX_AI_LOCATION}")
    print(f"Traffic lookback: {settings.TRAFFIC_LOOKBACK_DAYS} days")
    print("---")

    # Step 1: Resolve projects
    project_ids = resolve_projects(
        project_id=args.project,
        folder_id=args.folder,
        org_id=args.org,
    )
    print(f"Resolved {len(project_ids)} project(s) to scan")

    # Step 2: Apply project cap
    if args.max_projects and len(project_ids) > args.max_projects:
        print(f"Warning: capped to {args.max_projects} of {len(project_ids)} resolved projects")
        project_ids = project_ids[:args.max_projects]

    # Step 3: Parallel Cloud Run scan
    print(f"\nScanning {len(project_ids)} project(s) for public Cloud Run services...")
    all_findings = []

    with ThreadPoolExecutor(max_workers=settings.MAX_WORKERS) as executor:
        futures = {executor.submit(scan_cloud_run_services, pid): pid for pid in project_ids}
        for i, future in enumerate(as_completed(futures), 1):
            pid = futures[future]
            try:
                findings = future.result()
                print(f"✓ Scanned: {pid} — {len(findings)} public service(s) found ({i}/{len(project_ids)})")
                for f in findings:
                    f["project_id"] = pid
                all_findings.extend(findings)
            except Exception as e:
                print(f"✗ Failed: {pid} — {e}")

    # Step 4: Dry-run gate
    estimate = estimate_scan(project_ids, all_findings)
    if args.dry_run:
        print_dry_run_summary(estimate)
        confirm = input("\nProceed with full scan? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Dry run complete. No changes made.")
            return

    # Step 5: Traffic analysis
    print(f"\nAnalyzing traffic for {len(all_findings)} public service(s)...")
    for finding in all_findings:
        traffic = analyze_traffic(
            project_id=finding["project_id"],
            service_name=finding["name"],
            region=finding["region"],
            lookback_days=settings.TRAFFIC_LOOKBACK_DAYS,
        )
        finding.update(traffic)
        print(f"✓ {finding['name']} — {finding.get('request_count', 0)} requests | {finding.get('classification', 'Unknown')}")

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

    # Step 10: Single Gemini call — synthesize report only
    print(f"\nGenerating security report with {settings.GEMINI_MODEL}...")
    report = generate_report(
        classified_findings=classified,
        summary=summary,
        project_scope=project_scope,
        user_prompt=args.prompt,
        project_id=primary_project,
    )
    report_path = save_report(report, project_scope)
    print(f"Report saved to: {report_path}")


if __name__ == "__main__":
    main()
