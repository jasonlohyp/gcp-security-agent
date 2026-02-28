import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import settings
from tools.cloud_run_scanner import scan_cloud_run_services
from tools.project_resolver import resolve_projects
from tools.cost_estimator import estimate_scan, print_dry_run_summary

def parse_args():
    parser = argparse.ArgumentParser(
        description="GCP Security Agent — Cloud Run Public Exposure Scanner"
    )
    
    # Mutually exclusive group for project selection
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--project",
        help="GCP Project ID (overrides PROJECT_ID in .env)",
        default=None
    )
    group.add_argument(
        "--folder",
        help="GCP Folder ID to scan (resolves child projects)",
        default=None
    )
    group.add_argument(
        "--org",
        help="GCP Organization ID to scan (resolves all active projects)",
        default=None
    )

    parser.add_argument(
        "--prompt",
        help='Natural language prompt e.g. "Analyze Cloud Run public exposure"',
        required=True
    )

    # Production Guards
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Estimate costs and scope before proceeding"
    )
    parser.add_argument(
        "--max-projects",
        type=int,
        help="Cap the number of projects to scan",
        default=None
    )
    
    return parser.parse_args()

def main():
    args = parse_args()

    # Determine scope: CLI arg > .env > None
    project_id = args.project or (settings.PROJECT_ID if not any([args.folder, args.org]) else None)
    folder_id = args.folder or (settings.FOLDER_ID if not any([args.project, args.org]) else None)
    org_id = args.org or (settings.ORG_ID if not any([args.project, args.folder]) else None)

    if not any([project_id, folder_id, org_id]):
        raise ValueError("GCP scope is required. Pass --project, --folder, or --org (or set defaults in .env)")

    # Resolve projects
    projects = resolve_projects(project_id=project_id, folder_id=folder_id, org_id=org_id)
    
    # Apply project cap
    if args.max_projects and len(projects) > args.max_projects:
        print(f"WARNING: Capped to {args.max_projects} of {len(projects)} resolved projects.")
        projects = projects[:args.max_projects]
    
    print(f"Agent initialized | Prompt: {args.prompt}")
    print(f"Scope: {len(projects)} project(s) resolved")
    print(f"LLM: {settings.GEMINI_MODEL} @ {settings.VERTEX_AI_LOCATION}")
    print(f"Parallel workers: {settings.MAX_WORKERS}")
    print("---")
    
    all_findings = []
    
    # Parallel Project Scan
    print(f"Scanning {len(projects)} projects for public Cloud Run services...")
    with ThreadPoolExecutor(max_workers=settings.MAX_WORKERS) as executor:
        future_to_pid = {executor.submit(scan_cloud_run_services, pid): pid for pid in projects}
        
        for future in as_completed(future_to_pid):
            pid = future_to_pid[future]
            try:
                findings = future.result()
                all_findings.extend(findings)
                print(f"✓ Scanned project: {pid} — {len(findings)} public services found")
            except Exception as e:
                print(f"✗ FAILED to scan project {pid}: {e}")
    
    # Cost Estimation & Dry-Run flow
    estimate = estimate_scan(projects, all_findings)
    
    if args.dry_run:
        print_dry_run_summary(estimate)
        confirm = input("Proceed with Phase 3 (Traffic Analysis)? [y/N]: ").strip().lower()
        if confirm != 'y':
            print("Scan aborted by user.")
            sys.exit(0)
    
    if not all_findings:
        print("\nNo public Cloud Run services found across the resolved scope.")
        return

    # 1. Define columns and extract project names
    rows = []
    for f in all_findings:
        found_project = f['full_name'].split('/')[1]
        unauth_str = "YES" if f['unauthenticated'] else "NO"
        rows.append({
            "PROJECT": found_project,
            "SERVICE": f['name'],
            "REGION": f['region'],
            "INGRESS": f['ingress'],
            "UNAUTH?": unauth_str,
            "REASON": f['public_reason']
        })

    keys = ["PROJECT", "SERVICE", "REGION", "INGRESS", "UNAUTH?", "REASON"]
    
    # 2. Calculate max widths
    widths = {k: len(k) for k in keys}
    for row in rows:
        for k in keys:
            widths[k] = max(widths[k], len(str(row[k])))

    # 3. Print table
    header = " | ".join(k.ljust(widths[k]) for k in keys)
    print("\n" + header)
    print("-" * (sum(widths.values()) + (len(keys) - 1) * 3))
    
    for row in rows:
        line = " | ".join(str(row[k]).ljust(widths[k]) for k in keys)
        print(line)
    
    print(f"\nFound {len(all_findings)} public services across {len(projects)} projects.")
    print("Phase 3 (Traffic Correlation) would start now in a full run.")

if __name__ == "__main__":
    main()
