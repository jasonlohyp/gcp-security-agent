# file: agent/orchestrator.py
# Gemini 2.5 Flash report synthesizer.
# Receives pre-classified findings — does NOT classify or generate fix commands.
# Single LLM call per run regardless of number of services or projects.

import logging
from datetime import datetime
from pathlib import Path
from google import genai
from config import settings

logger = logging.getLogger(__name__)


def _load_risk_matrix() -> str:
    """Loads risk_matrix.md as context for the Gemini prompt."""
    matrix_path = Path(__file__).parent.parent / "config" / "risk_matrix.md"
    if matrix_path.exists():
        return matrix_path.read_text()
    logger.warning("risk_matrix.md not found — Gemini will reason without it")
    return ""


def _build_findings_context(classified_findings: list[dict]) -> str:
    """
    Formats pre-classified findings as structured text for the Gemini prompt.
    Uses lookback_days from each finding dict — never hardcoded.
    """
    lines = []
    for f in classified_findings:
        lookback_days = f.get("lookback_days", settings.TRAFFIC_LOOKBACK_DAYS)
        lines.append(f"""
Service:              {f.get('name')}
  Project:            {f.get('project_id')}
  Region:             {f.get('region')}
  Ingress:            {f.get('ingress')}
  Unauthenticated:    {f.get('unauthenticated')}
  Default SA:         {f.get('is_default_sa')}
  Service Account:    {f.get('service_account', 'unknown')}
  Requests ({lookback_days}d):   {f.get('request_count', 0)}
  Last Request:       {f.get('last_request_date', 'N/A')}
  Traffic Window:     {lookback_days} days
  Classification:     {f.get('classification', 'Unknown')}
  Risk Category:      {f.get('risk_category')}
  Risk Level:         {f.get('risk_level')}
  Triggered By:       {', '.join(f.get('triggered_dimensions', []))}
  Needs Remediation:  {f.get('needs_remediation')}
  Remediation:
{f.get('remediation', 'N/A')}
""")
    return "\n---\n".join(lines)


def _build_summary_context(summary: dict, lookback_days: int) -> str:
    """
    Formats the findings summary for the Gemini prompt.
    Includes the actual lookback window used in the scan.
    """
    return f"""
Scan Traffic Window:    {lookback_days} days
Total services found:   {summary.get('total', 0)}
Needs remediation:      {summary.get('needs_remediation', 0)}
Critical:               {summary.get('Critical', 0)}
High:                   {summary.get('High', 0)}
Medium:                 {summary.get('Medium', 0)}
Low:                    {summary.get('Low', 0)}
Minimal:                {summary.get('Minimal', 0)}
"""


def generate_report(
    classified_findings: list[dict],
    summary: dict,
    project_scope: str,
    user_prompt: str,
    project_id: str,
) -> str:
    """
    Generates a markdown security report using Gemini 2.5 Flash.
    Single LLM call — all classification and remediation already computed.

    Args:
        classified_findings: List of fully enriched + classified finding dicts
        summary:             Output from risk_classifier.summarise_findings()
        project_scope:       Human readable scope e.g. "project:my-project"
        user_prompt:         Original user prompt
        project_id:          GCP project ID for Vertex AI initialisation
                             Should be a project where you have roles/aiplatform.user
                             This is NOT required to be the same as the scan target.

    Returns:
        Markdown report as string

    Raises:
        PermissionError: if roles/aiplatform.user is missing on the Vertex AI project
        RuntimeError:    if Gemini model is not found or other API error occurs
    """
    risk_matrix = _load_risk_matrix()

    lookback_days = settings.TRAFFIC_LOOKBACK_DAYS
    if classified_findings:
        lookback_days = classified_findings[0].get("lookback_days", lookback_days)

    findings_context = _build_findings_context(classified_findings)
    summary_context = _build_summary_context(summary, lookback_days)

    system_prompt = f"""You are a GCP Cloud Security Analyst producing a professional security report.

Your role is to:
1. Write a clear executive summary
2. Present findings in a well-structured markdown report
3. Explain in plain language WHY each service is risky using the triggered dimensions provided
4. Present the pre-computed remediation commands exactly as provided — do not modify them
5. Add strategic recommendations based on patterns across all findings

You must follow this risk classification framework:
{risk_matrix}

IMPORTANT RULES:
- Do NOT re-classify services — use the risk_category and risk_level already provided
- Do NOT generate new gcloud commands — use the remediation commands already provided
- Do NOT omit any services from the report
- Always reference the actual traffic window ({lookback_days} days) — never assume 30 days
- Keep the executive summary concise (3-5 sentences)
- Use markdown tables for the findings summary
- Flag Critical and High findings prominently
"""

    user_message = f"""Generate a GCP Cloud Run Security Report based on the following:

USER REQUEST: {user_prompt}
SCOPE: {project_scope}
SCAN DATE: {datetime.now().strftime('%Y-%m-%d')}
TRAFFIC WINDOW: {lookback_days} days

SUMMARY:
{summary_context}

CLASSIFIED FINDINGS:
{findings_context}

Produce the report in this exact structure:
# GCP Cloud Run Security Report
## Executive Summary
## Findings Summary Table
## Critical & High Risk Services (detailed — include remediation commands)
## Medium Risk Services (detailed — include remediation commands)
## Low & Minimal Risk Services
## Strategic Recommendations
"""

    client = genai.Client(
        vertexai=True,
        project=project_id,
        location=settings.VERTEX_AI_LOCATION,
    )

    logger.info(f"Calling Gemini {settings.GEMINI_MODEL} for report generation...")

    try:
        response = client.models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=user_message,
            config={"system_instruction": system_prompt},
        )
    except Exception as e:
        error_str = str(e)

        if "403" in error_str or "PERMISSION_DENIED" in error_str:
            raise PermissionError(
                f"\n\n❌ PERMISSION DENIED — Gemini report generation failed.\n"
                f"   Vertex AI project used: {project_id}\n"
                f"   Missing role: roles/aiplatform.user\n\n"
                f"   Fix option 1 — Grant the role on your Vertex AI project:\n"
                f"   gcloud projects add-iam-policy-binding {project_id} \\\n"
                f"     --member='user:YOUR_EMAIL' \\\n"
                f"     --role='roles/aiplatform.user'\n\n"
                f"   Fix option 2 — Point to a project where you already have access:\n"
                f"   Set PROJECT_ID=your-personal-project in .env\n"
                f"   Note: PROJECT_ID is used for Gemini auth only, not the scan target.\n"
                f"   Use --project or --folder or --org to set the scan scope separately.\n"
            ) from e

        elif "404" in error_str or "not exist" in error_str:
            raise RuntimeError(
                f"\n\n❌ MODEL NOT FOUND — {settings.GEMINI_MODEL} not available "
                f"in region {settings.VERTEX_AI_LOCATION}.\n"
                f"   Check GEMINI_MODEL and VERTEX_AI_LOCATION values in your .env\n"
                f"   Current values: model={settings.GEMINI_MODEL} | "
                f"location={settings.VERTEX_AI_LOCATION}\n"
            ) from e

        else:
            raise RuntimeError(
                f"\n\n❌ Gemini API error — {error_str}\n"
            ) from e

    return response.text


def save_report(report: str, project_scope: str) -> str:
    """
    Saves the generated report to the output/ directory.

    Args:
        report:        Markdown report string
        project_scope: Used in the filename

    Returns:
        Path to the saved report file
    """
    from pathlib import Path

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_scope = project_scope.replace(" ", "_").replace(":", "").replace("/", "-")
    filename = f"report_{safe_scope}_{timestamp}.md"
    filepath = output_dir / filename

    filepath.write_text(report, encoding="utf-8")
    logger.info(f"Report saved to {filepath}")
    return str(filepath)
