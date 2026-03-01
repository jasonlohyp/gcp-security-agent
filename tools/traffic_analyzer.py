# file: tools/traffic_analyzer.py
# Correlates Cloud Run service traffic using the Cloud Logging API.
# Classifies each service as "Active" or "Inactive" based on request count
# within the configured lookback window.
# All time windows driven by settings.TRAFFIC_LOOKBACK_DAYS — never hardcoded.

import logging
from datetime import datetime, timezone, timedelta
from google.cloud import logging_v2
from config import settings

logger = logging.getLogger(__name__)


def analyze_traffic(
    project_id: str,
    service_name: str,
    region: str,
    lookback_days: int = settings.TRAFFIC_LOOKBACK_DAYS,
) -> dict:
    """
    Queries Cloud Logging to count requests for a Cloud Run service
    within the lookback window.

    Args:
        project_id:    GCP project ID
        service_name:  Cloud Run service name
        region:        Cloud Run service region
        lookback_days: Number of days to look back.
                       Defaults to settings.TRAFFIC_LOOKBACK_DAYS from .env.
                       Override by passing a value explicitly.

    Returns:
        dict with:
        - service_name:       Cloud Run service name
        - project_id:         GCP project ID
        - region:             Cloud Run region
        - request_count:      total requests in the lookback window
        - last_request_date:  ISO date string of most recent request, or None
        - lookback_days:      actual window used (passed through for reporting)
        - classification:     "Active" if request_count > 0, else "Inactive"
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

        # Dynamic time window — driven by lookback_days, never hardcoded
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
            max_results=1000,
        ))

        request_count = len(entries)
        result["request_count"] = request_count

        # Most recent request from first entry (DESCENDING order)
        if entries:
            latest_ts = entries[0].timestamp
            result["last_request_date"] = latest_ts.strftime("%Y-%m-%d")

        # Classification driven by request_count — no hardcoded label strings
        result["classification"] = "Active" if request_count > 0 else "Inactive"

    except Exception as e:
        logger.warning(
            f"Could not retrieve logs for {service_name} in {project_id}: {e}"
        )
        result["classification"] = "Unknown"

    return result
