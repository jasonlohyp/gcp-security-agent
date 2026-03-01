# file: tools/cost_estimator.py

from config import settings

def estimate_scan(project_ids: list[str], findings: list[dict]) -> dict:
    """
    Calculates a rough estimate of the scan runtime.
    BQ cost estimation removed as direct Logging is used for PoC.
    """
    project_count = len(project_ids)
    public_services_found = len(findings)
    
    # Heuristic: 3 seconds per project discovery / concurrency factor
    base_time_per_project = 3 
    estimated_run_time_mins = (project_count * base_time_per_project) / (settings.MAX_WORKERS * 60)
    
    return {
        "project_count": project_count,
        "public_services_found": public_services_found,
        "estimated_run_time_mins": max(0.1, estimated_run_time_mins) # Min 6 seconds
    }

def print_dry_run_summary(estimate: dict):
    """
    Prints the dry-run summary table to the terminal.
    """
    print("\n" + "="*50)
    print(" DRY-RUN ESTIMATION SUMMARY")
    print("="*50)
    
    rows = [
        ("Projects to scan", f"{estimate['project_count']}"),
        ("Public services found", f"{estimate['public_services_found']}"),
        ("Estimated remaining time", f"{estimate['estimated_run_time_mins']:.1f} mins"),
    ]
    
    for label, value in rows:
        print(f"{label:<28} : {value}")
    
    print("="*50)
    print("NOTICE: Cloud Logging queries are used for traffic analysis (no BQ cost).")
    print("Estimated time covers Cloud Run discovery only.")
    print("="*50 + "\n")
