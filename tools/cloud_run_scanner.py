# file: tools/cloud_run_scanner.py
# Scans all Cloud Run services in a GCP project for public exposure.
# Accepts project_number as a parameter — no extra Resource Manager API call needed.
# project_number is resolved once upstream in project_resolver.py.
#
# Ingress enum values from Cloud Run v2 API:
#   INGRESS_TRAFFIC_ALL                    -> ingress=all  (public internet)
#   INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER -> ingress=internal-and-cloud-load-balancing
#   INGRESS_TRAFFIC_INTERNAL_ONLY          -> ingress=internal (VPC only)
#
# IMPORTANT — internal services are NOT automatically skipped.
# ingress=internal + allUsers = Low risk finding (no identity control inside VPC).
# We only skip internal services that are also properly authenticated.

import logging
from google.cloud import run_v2
from google.iam.v1 import iam_policy_pb2

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


def scan_cloud_run_services(project_id: str, project_number: str) -> list[dict]:
    """
    Scans all Cloud Run services in a project for public exposure.

    Skips ONLY services that are both:
      - ingress=internal (INGRESS_TRAFFIC_INTERNAL_ONLY)
      - authenticated (no allUsers binding on roles/run.invoker)

    This ensures internal + unauthenticated services are captured
    as Low risk findings (categories: Internal Exposed / Internal Unauthenticated).

    Args:
        project_id:     GCP project ID e.g. "my-project"
        project_number: GCP project number e.g. "123456789012"
                        Passed in from project_resolver -- no extra API call needed.

    Returns:
        List of dicts with service metadata and exposure details.
    """
    client = run_v2.ServicesClient()
    parent = f"projects/{project_id}/locations/-"
    public_services = []

    # Build default SA from project_number passed in -- zero extra API calls
    default_sa = f"{project_number}-compute@developer.gserviceaccount.com"

    ingress_map = {
        "INGRESS_TRAFFIC_ALL":                    "all",
        "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER": "internal-and-cloud-load-balancing",
        "INGRESS_TRAFFIC_INTERNAL_ONLY":          "internal",
        "INGRESS_TRAFFIC_UNSPECIFIED":            "all",
    }

    try:
        services = client.list_services(parent=parent)

        for service in services:
            try:
                full_name  = service.name
                parts      = full_name.split("/")
                region     = parts[3]
                short_name = parts[5]

                ingress_name = service.ingress.name
                ingress_str  = ingress_map.get(ingress_name, "all")

                # ── IAM check (runs for ALL services including internal) ──────
                # Must run before the skip gate so internal+allUsers is caught.
                unauthenticated = False
                try:
                    request = iam_policy_pb2.GetIamPolicyRequest(resource=full_name)
                    policy  = client.get_iam_policy(request=request)
                    for binding in policy.bindings:
                        if binding.role == "roles/run.invoker":
                            if "allUsers" in binding.members:
                                unauthenticated = True
                                break
                except Exception as e:
                    logger.warning(f"Could not fetch IAM policy for {short_name}: {e}")

                # ── Skip ONLY internal + authenticated ────────────────────────
                # internal + allUsers  → Low finding, keep it
                # internal + IAM auth  → clean, skip
                if ingress_name == "INGRESS_TRAFFIC_INTERNAL_ONLY" and not unauthenticated:
                    logger.debug(f"Skipping {short_name} -- internal + authenticated (clean)")
                    continue

                # ── Service account check ─────────────────────────────────────
                service_account = service.template.service_account or default_sa
                is_default_sa = (
                    service_account == default_sa
                    or service_account == "default"
                    or not service_account
                )

                reason_parts = [f"ingress={ingress_str}"]
                if unauthenticated:
                    reason_parts.append("unauthenticated invocations enabled")
                if is_default_sa:
                    reason_parts.append("default compute SA in use")

                public_services.append({
                    "name":            short_name,
                    "full_name":       full_name,
                    "region":          region,
                    "ingress":         ingress_str,
                    "unauthenticated": unauthenticated,
                    "service_account": service_account,
                    "is_default_sa":   is_default_sa,
                    "public_reason":   " + ".join(reason_parts),
                })

            except Exception as e:
                logger.warning(f"Failed to process service {service.name}: {e}")
                continue

    except Exception as e:
        logger.error(f"Failed to list services for project {project_id}: {e}")
        raise

    return public_services
