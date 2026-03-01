import os
import datetime
from google import genai
from google.genai import types
from config import settings

def generate_report(findings: list[dict], project_scope: str, prompt: str) -> str:
    """
    Generates a security report using Gemini 2.5 Flash via Vertex AI.
    """
    # Use the first project_id from findings for the Vertex AI client
    # If no findings, we still need a project_id. 
    # In main.py, we only call this if there are findings.
    project_id = findings[0]['full_name'].split('/')[1] if findings else settings.PROJECT_ID
    
    client = genai.Client(vertexai=True, project=project_id, location=settings.VERTEX_AI_LOCATION)
    
    # Format findings for the prompt
    findings_text = ""
    for f in findings:
        project_id = f['full_name'].split('/')[1]
        findings_text += (
            f"- Service: {f['name']}\n"
            f"  Project: {project_id}\n"
            f"  Region: {f['region']}\n"
            f"  Ingress: {f['ingress']}\n"
            f"  Unauthenticated: {f['unauthenticated']}\n"
            f"  Request Count (30d): {f['request_count']}\n"
            f"  Classification: {f['classification']}\n"
            f"  Reason: {f['public_reason']}\n\n"
        )

    structured_prompt = f"""
You are a GCP Security Expert. Analyze the following Cloud Run public exposure findings and produce a professional security report.

USER PROMPT: {prompt}
PROJECT SCOPE: {project_scope}

FINDINGS:
{findings_text}

STRUCTURE THE REPORT EXACTLY AS FOLLOWS:
# GCP Cloud Run Security Report
## Executive Summary
(Provide a high-level overview of the findings and the risk to the organization)

## Findings Summary Table
(A markdown table summarizing all findings)

## Risky Services (detailed)
For each service classified as 'Risky' (no traffic in 30 days but publicly exposed):
   - Why it is risky: (Explain why a public but unused service is a high-risk target)
   - Evidence: (List ingress, auth status, and traffic data)
   - Remediation steps:
     ```bash
     # Restrict ingress and require authentication
     gcloud run services update SERVICE_NAME \\
       --ingress internal \\
       --region REGION \\
       --project PROJECT_ID
     ```

## Safe Services
(Briefly list services that are publicly exposed but have active traffic, noting they should still be monitored)

## Recommendations
(Provide 3-5 general security best practices for Cloud Run)

Generate the report in Markdown format.
"""

    try:
        response = client.models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=structured_prompt
        )
        return response.text
    except Exception as e:
        return f"Error generating report with Gemini: {e}"

def save_report(report: str, project_scope: str) -> str:
    """
    Saves the generated report to the output/ directory.
    """
    if not os.path.exists("output"):
        os.makedirs("output")
        
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"output/report_{project_scope}_{timestamp}.md"
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report)
        
    return filename
