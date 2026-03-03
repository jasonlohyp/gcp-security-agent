# file: tools/remediation_templates.py
# Generates ready-to-copy gcloud remediation commands per risk category.
# Uses Jinja2 templates — zero LLM calls, consistent output at any scale.
#
# Supports:
# - Cloud Run Services  (resource_type=cloud_run_service or unset)
# - Cloud Functions Gen 1 (resource_type=cloud_function_gen1)
# - Cloud Functions Gen 2 (resource_type=cloud_function_gen2)
#
# Gen 1 functions always include a migration warning block.
# The get_remediation() function routes to the correct template automatically.

from jinja2 import Template

# ============================================================
# CLOUD RUN SERVICE TEMPLATES
# ============================================================

CR_CRITICAL_HIGH_TEMPLATE = Template("""
# ============================================================
# REMEDIATION: {{ risk_category }}
# Resource: Cloud Run Service
# Service: {{ name }} | Project: {{ project_id }} | Region: {{ region }}
# ============================================================

# Step 1: Restrict ingress to load balancer only
gcloud run services update {{ name }} \\
  --ingress internal-and-cloud-load-balancing \\
  --region {{ region }} \\
  --project {{ project_id }}

# Step 2: Require authentication (remove allUsers binding)
gcloud run services remove-iam-policy-binding {{ name }} \\
  --region {{ region }} \\
  --project {{ project_id }} \\
  --member="allUsers" \\
  --role="roles/run.invoker"

{% if is_default_sa %}
# Step 3: Replace default compute SA with a dedicated service account
gcloud iam service-accounts create cr-{{ name | truncate(20, true, '') }} \\
  --display-name "Cloud Run SA for {{ name }}" \\
  --project {{ project_id }}

gcloud run services update {{ name }} \\
  --service-account cr-{{ name | truncate(20, true, '') }}@{{ project_id }}.iam.gserviceaccount.com \\
  --region {{ region }} \\
  --project {{ project_id }}
{% endif %}

# Step 4: (Recommended) Place service behind a Load Balancer
# This restricts ingress to internal-and-cloud-load-balancing and enables
# attachment of a security policy to the LB backend.
# Note: Load Balancer security policy attachment is not validated by this scan — verify manually.
# See: https://cloud.google.com/run/docs/securing/load-balancing
""")

CR_MEDIUM_IDENTITY_TEMPLATE = Template("""
# ============================================================
# REMEDIATION: {{ risk_category }}
# Resource: Cloud Run Service
# Service: {{ name }} | Project: {{ project_id }} | Region: {{ region }}
# ============================================================

# Step 1: Create a dedicated service account (replaces default compute SA)
gcloud iam service-accounts create cr-{{ name | truncate(20, true, '') }} \\
  --display-name "Cloud Run SA for {{ name }}" \\
  --project {{ project_id }}

# Step 2: Attach custom SA to the service
gcloud run services update {{ name }} \\
  --service-account cr-{{ name | truncate(20, true, '') }}@{{ project_id }}.iam.gserviceaccount.com \\
  --region {{ region }} \\
  --project {{ project_id }}

# Step 3: Restrict ingress to load balancer only
gcloud run services update {{ name }} \\
  --ingress internal-and-cloud-load-balancing \\
  --region {{ region }} \\
  --project {{ project_id }}
""")

CR_MEDIUM_LB_BYPASS_TEMPLATE = Template("""
# ============================================================
# REMEDIATION: {{ risk_category }}
# Resource: Cloud Run Service
# Service: {{ name }} | Project: {{ project_id }} | Region: {{ region }}
# ============================================================

# Step 1: Restrict ingress to internal-and-cloud-load-balancing
# Forces all traffic through your Load Balancer, preventing direct .run.app URL bypass attacks
gcloud run services update {{ name }} \\
  --ingress internal-and-cloud-load-balancing \\
  --region {{ region }} \\
  --project {{ project_id }}

# Step 2: Verify a security policy is attached to your LB backend
# Note: LB security policy attachment is not validated by this scan — check manually.
""")

CR_LOW_SHIELDED_TEMPLATE = Template("""
# ============================================================
# REVIEW: {{ risk_category }}
# Resource: Cloud Run Service
# Service: {{ name }} | Project: {{ project_id }} | Region: {{ region }}
# ============================================================

# Service is following enterprise standard configuration.
# Recommended review actions:

# 1. Verify a security policy is attached to your Load Balancer backend
# Note: LB security policy attachment is not validated by this scan — check manually.
# 1. Verify a security policy is attached to your Load Balancer backend
# Note: LB security policy attachment is not validated by this scan — check manually.

# 2. Confirm IAM invoker bindings are scoped correctly
gcloud run services get-iam-policy {{ name }} \\
  --region {{ region }} \\
  --project {{ project_id }}
""")

CR_LOW_INTERNAL_UNAUTH_TEMPLATE = Template("""
# ============================================================
# REMEDIATION: {{ risk_category }}
# Resource: Cloud Run Service
# Service: {{ name }} | Project: {{ project_id }} | Region: {{ region }}
# ============================================================

# Service is VPC-internal only (not reachable from internet).
# However it accepts unauthenticated requests — any internal workload
# can call it without identity verification.

# Step 1: Enable IAM authentication
gcloud run services remove-iam-policy-binding {{ name }} \\
  --region {{ region }} \\
  --project {{ project_id }} \\
  --member="allUsers" \\
  --role="roles/run.invoker"

# Step 2: Grant access to specific internal callers only
# Replace SERVICE_ACCOUNT with the SA of the calling service
gcloud run services add-iam-policy-binding {{ name }} \\
  --region {{ region }} \\
  --project {{ project_id }} \\
  --member="serviceAccount:CALLING_SERVICE_ACCOUNT@{{ project_id }}.iam.gserviceaccount.com" \\
  --role="roles/run.invoker"

# If unauthenticated access is intentional, document and accept the risk explicitly.
""")

CR_MINIMAL_TEMPLATE = Template("""
# ============================================================
# NO ACTION REQUIRED: {{ risk_category }}
# Resource: Cloud Run Service
# Service: {{ name }} | Project: {{ project_id }} | Region: {{ region }}
# ============================================================
# Service meets Gold Standard Zero Trust configuration.
# Continue to monitor for configuration drift.
""")

# ============================================================
# CLOUD FUNCTIONS TEMPLATES
# ============================================================

CF_GEN1_MIGRATION_BLOCK = """
# ============================================================
# ⚠️  GEN 1 FUNCTION — MIGRATION TO GEN 2 REQUIRED
# ============================================================
# Cloud Functions Gen 1 is legacy infrastructure.
# Google recommends migrating to Gen 2 for improved security,
# performance, longer timeouts, and Cloud Run-native architecture.
#
# Migration guide:
#   https://cloud.google.com/functions/docs/migrating
#
# Gen 2 overview:
#   https://cloud.google.com/functions/docs/concepts/version-comparison
#
# After migration, apply Cloud Run ingress and auth controls
# using the same patterns as Cloud Run Services.
# ============================================================
"""

CF_CRITICAL_HIGH_TEMPLATE = Template("""
# ============================================================
# REMEDIATION: {{ risk_category }}
# Resource: Cloud Function {{ '(Gen 1)' if gen1_migration_required else '(Gen 2)' }}
# Function: {{ name }} | Project: {{ project_id }} | Region: {{ region }}
# ============================================================
{% if gen1_migration_required %}
{{ gen1_migration_block }}
{% endif %}

# Step 1: Restrict ingress
gcloud functions deploy {{ name }} \\
  --ingress-settings internal-and-gclb \\
  --region {{ region }} \\
  --project {{ project_id }}

# Step 2: Require authentication (remove allUsers binding)
gcloud functions remove-iam-policy-binding {{ name }} \\
  --region {{ region }} \\
  --project {{ project_id }} \\
  --member="allUsers" \\
  --role="roles/cloudfunctions.invoker"

{% if is_default_sa %}
# Step 3: Replace default compute SA with a dedicated service account
gcloud iam service-accounts create cf-{{ name | truncate(20, true, '') }} \\
  --display-name "Cloud Function SA for {{ name }}" \\
  --project {{ project_id }}

gcloud functions deploy {{ name }} \\
  --service-account cf-{{ name | truncate(20, true, '') }}@{{ project_id }}.iam.gserviceaccount.com \\
  --region {{ region }} \\
  --project {{ project_id }}
{% endif %}
""")

CF_MEDIUM_IDENTITY_TEMPLATE = Template("""
# ============================================================
# REMEDIATION: {{ risk_category }}
# Resource: Cloud Function {{ '(Gen 1)' if gen1_migration_required else '(Gen 2)' }}
# Function: {{ name }} | Project: {{ project_id }} | Region: {{ region }}
# ============================================================
{% if gen1_migration_required %}
{{ gen1_migration_block }}
{% endif %}

# Step 1: Create a dedicated service account
gcloud iam service-accounts create cf-{{ name | truncate(20, true, '') }} \\
  --display-name "Cloud Function SA for {{ name }}" \\
  --project {{ project_id }}

# Step 2: Attach custom SA to the function
gcloud functions deploy {{ name }} \\
  --service-account cf-{{ name | truncate(20, true, '') }}@{{ project_id }}.iam.gserviceaccount.com \\
  --region {{ region }} \\
  --project {{ project_id }}

# Step 3: Restrict ingress
gcloud functions deploy {{ name }} \\
  --ingress-settings internal-and-gclb \\
  --region {{ region }} \\
  --project {{ project_id }}
""")

CF_MEDIUM_LB_BYPASS_TEMPLATE = Template("""
# ============================================================
# REMEDIATION: {{ risk_category }}
# Resource: Cloud Function {{ '(Gen 1)' if gen1_migration_required else '(Gen 2)' }}
# Function: {{ name }} | Project: {{ project_id }} | Region: {{ region }}
# ============================================================
{% if gen1_migration_required %}
{{ gen1_migration_block }}
{% endif %}

# Step 1: Restrict ingress to internal-and-gclb
gcloud functions deploy {{ name }} \\
  --ingress-settings internal-and-gclb \\
  --region {{ region }} \\
  --project {{ project_id }}

# Step 2: Verify a security policy is attached to your LB backend
# Note: LB security policy attachment is not validated by this scan — check manually.
""")

CF_LOW_INTERNAL_UNAUTH_TEMPLATE = Template("""
# ============================================================
# REMEDIATION: {{ risk_category }}
# Resource: Cloud Function {{ '(Gen 1)' if gen1_migration_required else '(Gen 2)' }}
# Function: {{ name }} | Project: {{ project_id }} | Region: {{ region }}
# ============================================================
{% if gen1_migration_required %}
{{ gen1_migration_block }}
{% endif %}

# Function is VPC-internal only but accepts unauthenticated requests.
# Any compromised internal workload can call this function without identity.

# Step 1: Enable authentication
gcloud functions remove-iam-policy-binding {{ name }} \\
  --region {{ region }} \\
  --project {{ project_id }} \\
  --member="allUsers" \\
  --role="roles/cloudfunctions.invoker"

# Step 2: Grant access to specific internal callers only
gcloud functions add-iam-policy-binding {{ name }} \\
  --region {{ region }} \\
  --project {{ project_id }} \\
  --member="serviceAccount:CALLING_SERVICE_ACCOUNT@{{ project_id }}.iam.gserviceaccount.com" \\
  --role="roles/cloudfunctions.invoker"
""")

CF_LOW_SHIELDED_TEMPLATE = Template("""
# ============================================================
# REVIEW: {{ risk_category }}
# Resource: Cloud Function {{ '(Gen 1)' if gen1_migration_required else '(Gen 2)' }}
# Function: {{ name }} | Project: {{ project_id }} | Region: {{ region }}
# ============================================================
{% if gen1_migration_required %}
{{ gen1_migration_block }}
{% endif %}

# Function is following enterprise standard configuration.

# 1. Verify a security policy is attached to your Load Balancer backend
# Note: LB security policy attachment is not validated by this scan — check manually.
# 1. Verify a security policy is attached to your Load Balancer backend
# Note: LB security policy attachment is not validated by this scan — check manually.

# 2. Confirm IAM invoker bindings are scoped correctly
gcloud functions get-iam-policy {{ name }} \\
  --region {{ region }} \\
  --project {{ project_id }}
""")

CF_MINIMAL_TEMPLATE = Template("""
# ============================================================
# NO ACTION REQUIRED: {{ risk_category }}
# Resource: Cloud Function {{ '(Gen 1)' if gen1_migration_required else '(Gen 2)' }}
# Function: {{ name }} | Project: {{ project_id }} | Region: {{ region }}
# ============================================================
{% if gen1_migration_required %}
{{ gen1_migration_block }}
{% endif %}
# Function meets Zero Trust configuration.
# Continue to monitor for configuration drift.
""")

# ============================================================
# ROUTING LOGIC
# ============================================================

# Cloud Run Service template map
CR_TEMPLATE_MAP = {
    "Critical: Exposed & Abandoned":       CR_CRITICAL_HIGH_TEMPLATE,
    "High: Public Direct Access":          CR_CRITICAL_HIGH_TEMPLATE,
    "High: LB Exposed & Abandoned":        CR_CRITICAL_HIGH_TEMPLATE,
    "Medium: LB Unauthenticated":          CR_MEDIUM_LB_BYPASS_TEMPLATE,
    "Medium: Identity Leakage":            CR_MEDIUM_IDENTITY_TEMPLATE,
    "Medium: Identity Leakage (LB)":       CR_MEDIUM_IDENTITY_TEMPLATE,
    "Medium: LB Bypass Risk":              CR_MEDIUM_LB_BYPASS_TEMPLATE,
    "Medium: Unknown Configuration":       CR_MEDIUM_LB_BYPASS_TEMPLATE,
    "Low: Shielded":                       CR_LOW_SHIELDED_TEMPLATE,
    "Low: Internal Exposed (Abandoned)":   CR_LOW_INTERNAL_UNAUTH_TEMPLATE,
    "Low: Internal Unauthenticated":       CR_LOW_INTERNAL_UNAUTH_TEMPLATE,
    "Minimal: Zero Trust":                 CR_MINIMAL_TEMPLATE,
}

# Cloud Functions template map (Gen1 + Gen2)
CF_TEMPLATE_MAP = {
    "Critical: Exposed & Abandoned":       CF_CRITICAL_HIGH_TEMPLATE,
    "High: Public Direct Access":          CF_CRITICAL_HIGH_TEMPLATE,
    "High: LB Exposed & Abandoned":        CF_CRITICAL_HIGH_TEMPLATE,
    "Medium: LB Unauthenticated":          CF_MEDIUM_LB_BYPASS_TEMPLATE,
    "Medium: Identity Leakage":            CF_MEDIUM_IDENTITY_TEMPLATE,
    "Medium: Identity Leakage (LB)":       CF_MEDIUM_IDENTITY_TEMPLATE,
    "Medium: LB Bypass Risk":              CF_MEDIUM_LB_BYPASS_TEMPLATE,
    "Medium: Unknown Configuration":       CF_MEDIUM_LB_BYPASS_TEMPLATE,
    "Low: Shielded":                       CF_LOW_SHIELDED_TEMPLATE,
    "Low: Internal Exposed (Abandoned)":   CF_LOW_INTERNAL_UNAUTH_TEMPLATE,
    "Low: Internal Unauthenticated":       CF_LOW_INTERNAL_UNAUTH_TEMPLATE,
    "Minimal: Zero Trust":                 CF_MINIMAL_TEMPLATE,
}


def get_remediation(finding: dict) -> str:
    """
    Returns ready-to-copy gcloud remediation commands for a classified finding.
    Routes to Cloud Run or Cloud Functions templates based on resource_type.

    Args:
        finding: Classified finding dict (must include risk_category)

    Returns:
        Formatted remediation string with correct gcloud commands for resource type
    """
    risk_category = finding.get("risk_category", "Medium: Unknown Configuration")
    resource_type = finding.get("resource_type", "cloud_run_service")

    if resource_type in ("cloud_function_gen1", "cloud_function_gen2"):
        template = CF_TEMPLATE_MAP.get(risk_category, CF_MEDIUM_LB_BYPASS_TEMPLATE)
        return template.render(
            **finding,
            gen1_migration_block=CF_GEN1_MIGRATION_BLOCK if finding.get("gen1_migration_required") else "",
        )
    else:
        template = CR_TEMPLATE_MAP.get(risk_category, CR_MEDIUM_LB_BYPASS_TEMPLATE)
        return template.render(**finding)
