# file: tools/risk_classifier.py
# Deterministic risk classifier for Cloud Run services.
# No LLM calls — pure Python logic based on config/risk_matrix.md
# This keeps classification consistent, fast, and free at org scale.

import logging

logger = logging.getLogger(__name__)


def classify_service(finding: dict) -> dict:
    """
    Classifies a Cloud Run service against the 6-tier risk matrix.
    Evaluates three dimensions in order: Network → Auth → Identity.

    Args:
        finding: Enriched dict from cloud_run_scanner + traffic_analyzer

    Returns:
        finding dict enriched with:
        - risk_category: str
        - risk_level: str (Critical | High | Medium | Low | Minimal)
        - triggered_dimensions: list[str]
        - needs_remediation: bool
    """
    ingress = finding.get("ingress", "").lower()
    unauthenticated = finding.get("unauthenticated", False)
    is_default_sa = finding.get("is_default_sa", False)
    request_count = finding.get("request_count", 0)

    triggered = []

    # --- Dimension 1: Network Perimeter ---
    if ingress == "all":
        triggered.append("Network: ingress=all (publicly accessible via internet)")
    elif ingress == "internal-and-cloud-load-balancing":
        triggered.append("Network: ingress=internal-and-cloud-load-balancing (LB required)")
    elif ingress == "internal":
        triggered.append("Network: ingress=internal (VPC only)")

    # --- Dimension 2: Access Control ---
    if unauthenticated:
        triggered.append("Auth: unauthenticated=True (no identity required)")
    else:
        triggered.append("Auth: unauthenticated=False (IAM required)")

    # --- Dimension 3: Identity ---
    if is_default_sa:
        triggered.append("Identity: Default compute SA detected (likely has Editor permissions)")
    else:
        triggered.append("Identity: Custom service account in use")

    # --- Classification Logic (first match wins) ---
    if ingress == "all" and unauthenticated and request_count == 0:
        category = "Critical: Exposed & Abandoned"
        risk_level = "Critical"
        needs_remediation = True

    elif ingress == "all" and unauthenticated and request_count > 0:
        category = "High: Public Direct Access"
        risk_level = "High"
        needs_remediation = True

    elif ingress == "all" and not unauthenticated and is_default_sa:
        category = "Medium: Identity Leakage"
        risk_level = "Medium"
        needs_remediation = True

    elif ingress == "all" and not unauthenticated:
        category = "Medium: LB Bypass Risk"
        risk_level = "Medium"
        needs_remediation = True

    elif ingress == "internal-and-cloud-load-balancing" and not unauthenticated:
        category = "Low: Shielded"
        risk_level = "Low"
        needs_remediation = False

    elif ingress == "internal":
        category = "Minimal: Zero Trust"
        risk_level = "Minimal"
        needs_remediation = False

    else:
        # Fallback — treat unknown as medium risk
        category = "Medium: Unknown Configuration"
        risk_level = "Medium"
        needs_remediation = True
        logger.warning(f"Unrecognised ingress config for {finding.get('name')}: {ingress}")

    return {
        **finding,
        "risk_category": category,
        "risk_level": risk_level,
        "triggered_dimensions": triggered,
        "needs_remediation": needs_remediation,
    }


def summarise_findings(classified_findings: list[dict]) -> dict:
    """
    Produces a summary count of findings by risk level.

    Returns:
        dict with counts per risk level and total needing remediation
    """
    summary = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Minimal": 0,
        "total": len(classified_findings),
        "needs_remediation": 0,
    }

    for f in classified_findings:
        level = f.get("risk_level", "Medium")
        if level in summary:
            summary[level] += 1
        if f.get("needs_remediation"):
            summary["needs_remediation"] += 1

    return summary
