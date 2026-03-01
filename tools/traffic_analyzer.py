import datetime
import time
from google.cloud import logging_v2
from google.api_core import exceptions as google_exceptions

def analyze_traffic(project_id: str, service_name: str, region: str, lookback_days: int = 30) -> dict:
    """
    Queries Cloud Logging for request logs to classify a service as Safe or Risky.
    Uses a simplified filter to avoid potential hangs and adds a timeout/limit.
    """
    client = logging_v2.Client(project=project_id)
    
    # Calculate timestamp for lookback
    lookback_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=lookback_days)
    timestamp_filter = lookback_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    
    # Use exact log name from gcloud output: run.googleapis.com%2Frequests
    log_id = "run.googleapis.com%2Frequests"
    
    log_filter = (
        f'resource.type="cloud_run_revision" '
        f'AND logName="projects/{project_id}/logs/{log_id}" '
        f'AND resource.labels.service_name="{service_name}" '
        f'AND resource.labels.location="{region}" '
        f'AND timestamp >= "{timestamp_filter}"'
    )
    
    result = {
        "service_name": service_name,
        "project_id": project_id,
        "region": region,
        "request_count": 0,
        "last_request_date": "N/A",
        "classification": "Risky",
        "lookback_days": lookback_days
    }
    
    try:
        # We fetch a limited number of entries for PoC to avoid potential hangs 
        # with huge result sets. If it's more than 100, we'll just say 100+.
        # order_by is important to get the most recent one first.
        entries = client.list_entries(
            filter_=log_filter, 
            order_by=logging_v2.DESCENDING,
            page_size=100
        )
        
        count = 0
        last_timestamp = None
        
        # We only iterate up to 100 entries for the count in PoC
        for entry in entries:
            if count == 0:
                last_timestamp = entry.timestamp
            count += 1
            if count >= 100:
                break
                
        result["request_count"] = count
        if last_timestamp:
            result["last_request_date"] = last_timestamp.strftime('%Y-%m-%d')
            result["classification"] = "Safe"
            
    except google_exceptions.PermissionDenied:
        print(f"Warning: Permission denied for logs in project {project_id}")
        result["classification"] = "Unknown"
    except Exception as e:
        print(f"Warning: Error analyzing traffic for {service_name} in {project_id}: {e}")
        result["classification"] = "Unknown"
        
    return result
