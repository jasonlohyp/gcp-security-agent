# file: tools/remediation_templates.py
# Generates ready-to-copy gcloud remediation commands per risk category.
# Uses Jinja2 templates — zero LLM calls, consistent output at any scale.

from jinja2 import Template

# --- Templates per risk category ---

CRITICAL_HIGH_TEMPLATE = Template("""
# ============================================================
# REMEDIATION: {{ risk_category }}
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

# Step 4: (Recommended) Set up a Load Balancer with Cloud Armor
# See: https://cloud.google.com/run/docs/securing/load-balancing
""")

MEDIUM_IDENTITY_TEMPLATE = Template("""
# ============================================================
# REMEDIATION: {{ risk_category }}
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

MEDIUM_LB_BYPASS_TEMPLATE = Template("""
# ============================================================
# REMEDIATION: {{ risk_category }}
# Service: {{ name }} | Project: {{ project_id }} | Region: {{ region }}
# ============================================================

# Step 1: Restrict ingress to internal-and-cloud-load-balancing
# This forces all traffic through your Load Balancer (and Cloud Armor WAF)
# preventing direct .run.app URL bypass attacks
gcloud run services update {{ name }} \\
  --ingress internal-and-cloud-load-balancing \\
  --region {{ region }} \\
  --project {{ project_id }}

# Step 2: Verify Cloud Armor policy is attached to your LB backend
# See: https://cloud.google.com/armor/docs/configure-security-policies
""")

LOW_SHIELDED_TEMPLATE = Template("""
# ============================================================
# REVIEW: {{ risk_category }}
# Service: {{ name }} | Project: {{ project_id }} | Region: {{ region }}
# ============================================================

# Service is following enterprise standard configuration.
# Recommended review actions:

# 1. Verify Cloud Armor security policy is attached to your Load Balancer
gcloud compute backend-services list --project {{ project_id }}

# 2. Confirm IAM invoker bindings are scoped correctly
gcloud run services get-iam-policy {{ name }} \\
  --region {{ region }} \\
  --project {{ project_id }}
""")

MINIMAL_TEMPLATE = Template("""
# ============================================================
# NO ACTION REQUIRED: {{ risk_category }}
# Service: {{ name }} | Project: {{ project_id }} | Region: {{ region }}
# ============================================================
# Service meets Gold Standard Zero Trust configuration.
# Continue to monitor for configuration drift.
""")

# --- Category to template mapping ---
TEMPLATE_MAP = {
    "Critical: Exposed & Abandoned": CRITICAL_HIGH_TEMPLATE,
    "High: Public Direct Access": CRITICAL_HIGH_TEMPLATE,
    "Medium: Identity Leakage": MEDIUM_IDENTITY_TEMPLATE,
    "Medium: LB Bypass Risk": MEDIUM_LB_BYPASS_TEMPLATE,
    "Medium: Unknown Configuration": MEDIUM_LB_BYPASS_TEMPLATE,
    "Low: Shielded": LOW_SHIELDED_TEMPLATE,
    "Minimal: Zero Trust": MINIMAL_TEMPLATE,
}


def get_remediation(finding: dict) -> str:
    """
    Returns ready-to-copy gcloud remediation commands for a classified finding.

    Args:
        finding: Classified finding dict (must include risk_category)

    Returns:
        Formatted remediation string
    """
    risk_category = finding.get("risk_category", "Medium: Unknown Configuration")
    template = TEMPLATE_MAP.get(risk_category, MEDIUM_LB_BYPASS_TEMPLATE)
    return template.render(**finding)
