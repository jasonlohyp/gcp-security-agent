import logging
from google.cloud import run_v2
from google.iam.v1 import iam_policy_pb2

# Configure basic logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

def scan_cloud_run_services(project_id: str) -> list[dict]:
    """
    Scans all Cloud Run services in a project discovery public exposure.
    
    Returns a list of dictionaries containing service metadata and exposure details.
    """
    client = run_v2.ServicesClient()
    parent = f"projects/{project_id}/locations/-"
    
    public_services = []
    
    try:
        # 1. List all services across all regions
        services = client.list_services(parent=parent)
        
        for service in services:
            try:
                # Service name parts: projects/{project}/locations/{location}/services/{service}
                full_name = service.name
                parts = full_name.split('/')
                region = parts[3]
                short_name = parts[5]
                
                # Ingress mapping (using protoc enum names/values)
                ingress_val = service.ingress.name
                # Options: INGRESS_TRAFFIC_ALL, INGRESS_TRAFFIC_INTERNAL_ONLY, INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER
                is_internal = "INTERNAL" in ingress_val
                
                # 2. Check IAM Policy for unauthenticated access
                request = iam_policy_pb2.GetIamPolicyRequest(resource=full_name)
                policy = client.get_iam_policy(request=request)
                
                unauthenticated = False
                for binding in policy.bindings:
                    if binding.role == "roles/run.invoker":
                        if "allUsers" in binding.members:
                            unauthenticated = True
                            break
                
                # 3. Filter and categorize
                if not is_internal:
                    reason_parts = []
                    if "ALL" in ingress_val:
                        reason_parts.append("ingress=all")
                    elif "LOAD_BALANCER" in ingress_val:
                        reason_parts.append("ingress=internal-and-cloud-load-balancing")
                    
                    if unauthenticated:
                        reason_parts.append("unauthenticated invocations enabled")
                    
                    public_services.append({
                        "name": short_name,
                        "full_name": full_name,
                        "region": region,
                        "ingress": ingress_val.replace("INGRESS_TRAFFIC_", "").lower().replace("_", "-"),
                        "unauthenticated": unauthenticated,
                        "public_reason": " + ".join(reason_parts) if reason_parts else "exposed"
                    })
                    
            except Exception as e:
                logger.warning(f"Failed to process service {service.name}: {e}")
                continue
                
    except Exception as e:
        logger.error(f"Failed to list services for project {project_id}: {e}")
        raise
        
    return public_services
