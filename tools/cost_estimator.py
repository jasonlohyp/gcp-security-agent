# file: tools/cost_estimator.py
# Dry-run scope estimator for the GCP Security Agent.
# Cloud Logging API is free — no cost estimation needed.
# This module estimates run time and scope only.

from config import settings


def estimate_scan(project_ids: list[str], findings: list[dict]) -> dict:
    """
    Estimates the scope and run time of a full scan.
    Cloud Logging API is free so no cost estimate is needed.

    Args:
        project_ids: List of resolved project IDs to scan
        findings: Public Cloud Run services found by the scanner

    Returns:
        dict with scope and time estimates
    """
    project_count = len(project_ids)
    public_services = len(findings)

    # Estimate run time: 3s per project divided by parallel workers
    estimated_run_time_mins = round(
        (project_count * 3) / (settings.MAX_WORKERS * 60), 1
    )

    return {
        "project_count": project_count,
        "public_services_found": public_services,
        "logging_queries_to_run": public_services,
        "estimated_run_time_mins": estimated_run_time_mins,
    }


def print_dry_run_summary(estimate: dict):
    """Prints a clean dry-run summary table to terminal."""
    width = 44
    print()
    print("=" * width)
    print(" DRY-RUN ESTIMATION SUMMARY")
    print("=" * width)
    print(f" Projects to scan          : {estimate['project_count']}")
    print(f" Public services found     : {estimate['public_services_found']}")
    print(f" Logging queries to run    : {estimate['logging_queries_to_run']}")
    print(f" Estimated run time        : {estimate['estimated_run_time_mins']} mins")
    print("=" * width)
    print(" NOTE: Cloud Logging API is free.")
    print(" Cost: ~$0.01 flat for the Gemini report call.")
    print("=" * width)
