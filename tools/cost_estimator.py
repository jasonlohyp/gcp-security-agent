from config import settings

def estimate_scan(project_ids: list[str], findings: list[dict]) -> dict:
    """
    Calculates a rough estimate of the scan cost and runtime.
    """
    project_count = len(project_ids)
    public_services_found = len(findings)
    
    # Phase 3 will run 1 BQ query per public service found
    bq_queries_to_run = public_services_found
    
    estimated_bq_gb = bq_queries_to_run * settings.DEFAULT_BQ_GB_PER_QUERY
    estimated_bq_cost_usd = estimated_bq_gb * settings.BQ_COST_PER_GB
    
    # Heuristic: 3 seconds per project discovery / concurrency factor
    # (Discovery involves listing services and fetching IAM policies)
    base_time_per_project = 3 
    estimated_run_time_mins = (project_count * base_time_per_project) / (settings.MAX_WORKERS * 60)
    
    return {
        "project_count": project_count,
        "public_services_found": public_services_found,
        "bq_queries_to_run": bq_queries_to_run,
        "estimated_bq_gb": estimated_bq_gb,
        "estimated_bq_cost_usd": estimated_bq_cost_usd,
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
        ("BigQuery queries planned", f"{estimate['bq_queries_to_run']}"),
        ("Estimated BQ data scanned", f"{estimate['estimated_bq_gb']:.2f} GB"),
        ("Estimated BQ cost (USD)", f"${estimate['estimated_bq_cost_usd']:.4f}"),
        ("Estimated remaining time", f"{estimate['estimated_run_time_mins']:.1f} mins"),
    ]
    
    for label, value in rows:
        print(f"{label:<28} : {value}")
    
    print("="*50)
    print("NOTICE: Costs are estimates based on $5/TB BQ pricing.")
    print("Estimated time covers Cloud Run discovery only.")
    print("="*50 + "\n")
