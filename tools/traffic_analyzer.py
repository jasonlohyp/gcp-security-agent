# file: tools/traffic_analyzer.py
# Correlates Cloud Run / Cloud Functions traffic using the Cloud Logging API.
#
# IMPORTANT — quota-safe design:
# Uses ONE Cloud Logging API call per project (batch query) regardless of
# how many services/functions are in that project.
#
# Before: 50 services × 1 call = 50 calls per project → hits 60 req/min quota
# After:  50 services × 0 calls + 1 batch call = 1 call per project → safe at any scale
#
# This avoids impacting production projects with burst logging read traffic.
# Cloud Logging quota: 60 read requests per minute per project.
# At 1 call per project this limit is never approached.

import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from google.cloud import logging_v2
from config import settings

logger = logging.getLogger(__name__)


def analyze_traffic_batch(
    project_id: str,
    findings: list[dict],
    lookback_days: int = settings.TRAFFIC_LOOKBACK_DAYS,
) -> list[dict]:
    """
    Fetches traffic for ALL findings in a project in a SINGLE Cloud Logging API call.
    Distributes results back to each finding by service name.

    This is the quota-safe approach — 1 API call per project regardless of
    how many services or functions are being analysed.

    Args:
        project_id:    GCP project ID
        findings:      List of finding dicts for this project (from scanner)
        lookback_days: Lookback window in days

    Returns:
        Same findings list enriched with traffic data:
        - request_count:      requests found within lookback window (capped at 500)
        - last_request_date:  ISO date string of most recent request, or None
        - lookback_days:      actual window used
        - classification:     "Active" | "Inactive" | "Unknown"
    """
    if not findings:
        return findings

    # Initialise all findings with default traffic values
    for f in findings:
        f.update({
            "request_count": 0,
            "last_request_date": None,
            "lookback_days": lookback_days,
            "classification": "Inactive",
        })

    try:
        client = logging_v2.Client(project=project_id)

        since = datetime.now(timezone.utc) - timedelta(days=lookback_days)
        since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Build service name list for OR filter — one query covers all services
        service_names = list({f["name"] for f in findings})
        name_filter = " OR ".join(
            f'resource.labels.service_name="{name}"'
            for name in service_names
        )

        # Single batch query for all services in this project
        log_filter = (
            f'resource.type="cloud_run_revision" '
            f'AND logName="projects/{project_id}/logs/run.googleapis.com%2Frequests" '
            f'AND ({name_filter}) '
            f'AND timestamp>="{since_str}"'
        )

        # Cap at 500 entries per project — enough for Active/Inactive classification
        # across all services while keeping the single query lightweight
        entries = list(client.list_entries(
            filter_=log_filter,
            order_by=logging_v2.DESCENDING,
            max_results=500,
        ))

        # Distribute log entries back to findings by service name
        # Build per-service counts and last-seen dates from the batch result
        service_counts: dict[str, int] = defaultdict(int)
        service_last_seen: dict[str, str] = {}

        for entry in entries:
            try:
                svc_name = entry.resource.labels.get("service_name", "")
                if svc_name:
                    service_counts[svc_name] += 1
                    # First time we see this service = most recent (DESCENDING order)
                    if svc_name not in service_last_seen:
                        service_last_seen[svc_name] = entry.timestamp.strftime("%Y-%m-%d")
            except Exception:
                continue

        # Enrich each finding with its traffic data
        for f in findings:
            name = f["name"]
            count = service_counts.get(name, 0)
            f["request_count"] = count
            f["last_request_date"] = service_last_seen.get(name)
            f["classification"] = "Active" if count > 0 else "Inactive"

    except Exception as e:
        logger.warning(
            f"Could not retrieve batch traffic logs for project {project_id}: {e}. "
            f"All {len(findings)} services in this project classified as Unknown."
        )
        for f in findings:
            f["classification"] = "Unknown"

    return findings


def analyze_traffic(
    project_id: str,
    service_name: str,
    region: str,
    lookback_days: int = settings.TRAFFIC_LOOKBACK_DAYS,
) -> dict:
    """
    Single-service traffic lookup. Kept for backwards compatibility.
    For multi-service projects use analyze_traffic_batch() instead.

    Args:
        project_id:    GCP project ID
        service_name:  Cloud Run service name
        region:        Cloud Run region
        lookback_days: Lookback window in days

    Returns:
        dict with request_count, last_request_date, lookback_days, classification
    """
    result = {
        "service_name": service_name,
        "project_id": project_id,
        "region": region,
        "request_count": 0,
        "last_request_date": None,
        "lookback_days": lookback_days,
        "classification": "Inactive",
    }

    try:
        client = logging_v2.Client(project=project_id)
        since = datetime.now(timezone.utc) - timedelta(days=lookback_days)
        since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        log_filter = (
            f'resource.type="cloud_run_revision" '
            f'AND logName="projects/{project_id}/logs/run.googleapis.com%2Frequests" '
            f'AND resource.labels.service_name="{service_name}" '
            f'AND resource.labels.location="{region}" '
            f'AND timestamp>="{since_str}"'
        )

        entries = list(client.list_entries(
            filter_=log_filter,
            order_by=logging_v2.DESCENDING,
            max_results=100,
        ))

        result["request_count"] = len(entries)
        if entries:
            result["last_request_date"] = entries[0].timestamp.strftime("%Y-%m-%d")
        result["classification"] = "Active" if len(entries) > 0 else "Inactive"

    except Exception as e:
        logger.warning(f"Could not retrieve logs for {service_name}: {e}")
        result["classification"] = "Unknown"

    return result
