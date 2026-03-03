# file: tools/cloud_functions_scanner.py
# Scans Cloud Functions (Gen 1 and Gen 2) in a GCP project for public exposure.
# Returns findings in the same dict shape as cloud_run_scanner.py so the rest
# of the pipeline (traffic_analyzer, risk_classifier, remediation_templates)
# works without any changes.
#
# Gen 1: cloudfunctions.googleapis.com v1 API
# Gen 2: cloudfunctions.googleapis.com v2 API (built on Cloud Run under the hood)
#
# Key differences from Cloud Run Services:
# - IAM role to check: roles/cloudfunctions.invoker (not roles/run.invoker)
# - Ingress enum names differ slightly between Gen1 and Gen2 — normalised here
# - Gen 1 functions are flagged for migration to Gen 2
#
# Skip logic (mirrors cloud_run_scanner.py):
# - internal + authenticated  → skip (clean, nothing to report)
# - internal + unauthenticated → keep as Low finding
# - all other ingress values  → always keep
#
# Bug fixes vs original:
# 1. Double IAM call eliminated — result is captured once and reused at skip gate
# 2. Default SA detection uses exact pattern match on {number}-compute@developer.gserviceaccount.com
#    instead of broad domain suffix check that could false-positive on custom SAs

import logging
import re
from google.cloud import functions_v1
from google.cloud import functions_v2
from google.iam.v1 import iam_policy_pb2

logger = logging.getLogger(__name__)

# Gen 1 ingress settings map
# https://cloud.google.com/functions/docs/reference/rest/v1/projects.locations.functions
GEN1_INGRESS_MAP = {
    "ALLOW_ALL":                   "all",
    "ALLOW_INTERNAL_ONLY":         "internal",
    "ALLOW_INTERNAL_AND_GCLB":     "internal-and-cloud-load-balancing",
    "INGRESS_SETTINGS_UNSPECIFIED": "all",
}

# Gen 2 ingress settings map — same values as Cloud Run
GEN2_INGRESS_MAP = {
    "ALLOW_ALL":                   "all",
    "ALLOW_INTERNAL_ONLY":         "internal",
    "ALLOW_INTERNAL_AND_GCLB":     "internal-and-cloud-load-balancing",
    "INGRESS_SETTINGS_UNSPECIFIED": "all",
}

GEN1_MIGRATION_NOTE = (
    "⚠️  GEN 1 FUNCTION — MIGRATION REQUIRED\n"
    "Google Cloud Functions Gen 1 is legacy. Gen 2 offers better performance,\n"
    "longer timeouts, and improved security posture (built on Cloud Run).\n"
    "Migration guide: https://cloud.google.com/functions/docs/migrating\n"
    "Gen 2 announcement: https://cloud.google.com/blog/products/serverless/"
    "cloud-functions-2nd-generation-now-generally-available\n"
)

# Exact pattern for default compute SA: {project_number}-compute@developer.gserviceaccount.com
_DEFAULT_SA_RE = re.compile(r"^\d+-compute@developer\.gserviceaccount\.com$")


def _is_default_sa(service_account: str, default_sa: str) -> bool:
    """
    Returns True if service_account is the default compute SA.
    Matches the exact {number}-compute@developer.gserviceaccount.com pattern only.
    Avoids false positives on custom SAs that happen to be hosted on the same domain.
    """
    if not service_account:
        return True
    if service_account == default_sa or service_account == "default":
        return True
    return bool(_DEFAULT_SA_RE.match(service_account))


def _check_gen1_iam(client: functions_v1.CloudFunctionsServiceClient, full_name: str) -> bool:
    """Returns True if Gen1 function allows unauthenticated (allUsers) invocations."""
    try:
        request = iam_policy_pb2.GetIamPolicyRequest(resource=full_name)
        policy = client.get_iam_policy(request=request)
        for binding in policy.bindings:
            if binding.role == "roles/cloudfunctions.invoker":
                if "allUsers" in binding.members:
                    return True
    except Exception as e:
        logger.warning(f"Could not fetch IAM policy for {full_name}: {e}")
    return False


def _check_gen2_iam(client: functions_v2.FunctionServiceClient, full_name: str) -> bool:
    """Returns True if Gen2 function allows unauthenticated (allUsers) invocations."""
    try:
        request = iam_policy_pb2.GetIamPolicyRequest(resource=full_name)
        policy = client.get_iam_policy(request=request)
        for binding in policy.bindings:
            # Gen2 functions use roles/run.invoker (built on Cloud Run)
            if binding.role in ("roles/cloudfunctions.invoker", "roles/run.invoker"):
                if "allUsers" in binding.members:
                    return True
    except Exception as e:
        logger.warning(f"Could not fetch IAM policy for {full_name}: {e}")
    return False


def scan_cloud_functions_gen1(project_id: str, project_number: str) -> list[dict]:
    """
    Scans all Cloud Functions Gen 1 in a project for public exposure.

    Skip logic:
      internal + authenticated  → skip (clean)
      internal + unauthenticated → keep as Low finding
      all other ingress          → always keep

    Args:
        project_id:     GCP project ID
        project_number: GCP project number (from project_resolver)

    Returns:
        List of finding dicts — same shape as cloud_run_scanner output.
        Includes resource_type="cloud_function_gen1" and gen1_migration_required=True.
    """
    client = functions_v1.CloudFunctionsServiceClient()
    parent = f"projects/{project_id}/locations/-"
    default_sa = f"{project_number}-compute@developer.gserviceaccount.com"
    findings = []

    try:
        for fn in client.list_functions(request={"parent": parent}):
            try:
                # projects/{project}/locations/{region}/functions/{name}
                parts      = fn.name.split("/")
                region     = parts[3]
                short_name = parts[5]

                ingress_name = fn.ingress_settings.name
                ingress_str  = GEN1_INGRESS_MAP.get(ingress_name, "all")

                # ── IAM check — runs first for all services ───────────────────
                # Captured once here; reused at the skip gate and in the finding.
                unauthenticated = _check_gen1_iam(client, fn.name)

                # ── Skip only internal + authenticated ────────────────────────
                if ingress_str == "internal" and not unauthenticated:
                    logger.debug(f"Skipping Gen1 {short_name} -- internal + authenticated (clean)")
                    continue

                # ── Service account check ─────────────────────────────────────
                service_account = fn.service_account_email or default_sa
                use_default_sa  = _is_default_sa(service_account, default_sa)

                reason_parts = [f"ingress={ingress_str}"]
                if unauthenticated:
                    reason_parts.append("unauthenticated invocations enabled")
                if use_default_sa:
                    reason_parts.append("default compute SA in use")
                reason_parts.append("Gen1 — migration required")

                findings.append({
                    "name":                   short_name,
                    "full_name":              fn.name,
                    "region":                 region,
                    "ingress":                ingress_str,
                    "unauthenticated":        unauthenticated,
                    "service_account":        service_account,
                    "is_default_sa":          use_default_sa,
                    "public_reason":          " + ".join(reason_parts),
                    "resource_type":          "cloud_function_gen1",
                    "gen1_migration_required": True,
                    "gen1_migration_note":    GEN1_MIGRATION_NOTE,
                })

            except Exception as e:
                logger.warning(f"Failed to process Gen1 function {fn.name}: {e}")
                continue

    except Exception as e:
        logger.warning(f"Could not scan Gen1 functions for {project_id}: {e}")
        # Non-fatal — project may not have Cloud Functions API enabled

    return findings


def scan_cloud_functions_gen2(project_id: str, project_number: str) -> list[dict]:
    """
    Scans all Cloud Functions Gen 2 in a project for public exposure.

    Gen 2 functions are built on Cloud Run — same ingress values, same risk profile.

    Skip logic:
      internal + authenticated  → skip (clean)
      internal + unauthenticated → keep as Low finding
      all other ingress          → always keep

    Args:
        project_id:     GCP project ID
        project_number: GCP project number (from project_resolver)

    Returns:
        List of finding dicts — same shape as cloud_run_scanner output.
        Includes resource_type="cloud_function_gen2".
    """
    client = functions_v2.FunctionServiceClient()
    parent = f"projects/{project_id}/locations/-"
    default_sa = f"{project_number}-compute@developer.gserviceaccount.com"
    findings = []

    try:
        for fn in client.list_functions(request={"parent": parent}):
            try:
                parts      = fn.name.split("/")
                region     = parts[3]
                short_name = parts[5]

                # Gen2 uses service_config for ingress and SA
                service_config = fn.service_config
                ingress_name   = service_config.ingress_settings.name
                ingress_str    = GEN2_INGRESS_MAP.get(ingress_name, "all")

                # ── IAM check — runs first for all services ───────────────────
                # Captured once here; reused at the skip gate and in the finding.
                unauthenticated = _check_gen2_iam(client, fn.name)

                # ── Skip only internal + authenticated ────────────────────────
                if ingress_str == "internal" and not unauthenticated:
                    logger.debug(f"Skipping Gen2 {short_name} -- internal + authenticated (clean)")
                    continue

                # ── Service account check ─────────────────────────────────────
                service_account = service_config.service_account_email or default_sa
                use_default_sa  = _is_default_sa(service_account, default_sa)

                reason_parts = [f"ingress={ingress_str}"]
                if unauthenticated:
                    reason_parts.append("unauthenticated invocations enabled")
                if use_default_sa:
                    reason_parts.append("default compute SA in use")

                findings.append({
                    "name":                   short_name,
                    "full_name":              fn.name,
                    "region":                 region,
                    "ingress":                ingress_str,
                    "unauthenticated":        unauthenticated,
                    "service_account":        service_account,
                    "is_default_sa":          use_default_sa,
                    "public_reason":          " + ".join(reason_parts),
                    "resource_type":          "cloud_function_gen2",
                    "gen1_migration_required": False,
                })

            except Exception as e:
                logger.warning(f"Failed to process Gen2 function {fn.name}: {e}")
                continue

    except Exception as e:
        logger.warning(f"Could not scan Gen2 functions for {project_id}: {e}")
        # Non-fatal — project may not have Cloud Functions API enabled

    return findings


def scan_cloud_functions(project_id: str, project_number: str) -> list[dict]:
    """
    Scans both Gen 1 and Gen 2 Cloud Functions in a project.
    Combines results into a single list in the same format as cloud_run_scanner.

    Args:
        project_id:     GCP project ID
        project_number: GCP project number (from project_resolver)

    Returns:
        Combined list of Gen1 + Gen2 findings
    """
    gen1 = scan_cloud_functions_gen1(project_id, project_number)
    gen2 = scan_cloud_functions_gen2(project_id, project_number)

    total = len(gen1) + len(gen2)
    if total > 0:
        logger.info(
            f"{project_id}: found {len(gen1)} Gen1 + {len(gen2)} Gen2 functions to scan"
        )

    return gen1 + gen2
