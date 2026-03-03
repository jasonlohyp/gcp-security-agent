# file: agent/orchestrator.py
# LLM report synthesizer + HTML report generator.
#
# OUTPUT STRATEGY:
#   --project  → per-project HTML report only (no org summary)
#   --folder   → per-project HTML per project (Medium+ only) + folder summary HTML
#   --org      → per-project HTML per project (Medium+ only) + org summary HTML
#
# LLM ROLE: single Gemini call per run — narrative synthesis only.
# All risk classification and remediation commands are pre-computed in Python.

import json
import logging
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from google import genai
from config import settings

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _load_risk_matrix() -> str:
    path = Path(__file__).parent.parent / "config" / "risk_matrix.md"
    if path.exists():
        return path.read_text()
    logger.warning("risk_matrix.md not found — Gemini will reason without it")
    return ""


def _load_template(name: str) -> str:
    """Loads an HTML template from agent/templates/."""
    path = Path(__file__).parent / "templates" / name
    if path.exists():
        return path.read_text()
    raise FileNotFoundError(f"Template not found: {path}")


def _ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _safe_scope(project_scope: str) -> str:
    return project_scope.replace(" ", "_").replace(":", "").replace("/", "-")


def _output_dir() -> Path:
    d = Path("output")
    d.mkdir(exist_ok=True)
    return d


# ──────────────────────────────────────────────────────────────────────────────
# GEMINI: PROMPT BUILDERS
# ──────────────────────────────────────────────────────────────────────────────

def _build_findings_context(findings: list[dict]) -> str:
    lines = []
    for f in findings:
        ld = f.get("lookback_days", settings.TRAFFIC_LOOKBACK_DAYS)
        lines.append(f"""
Service:              {f.get('name')}
  Project:            {f.get('project_id')}
  Region:             {f.get('region')}
  Resource Type:      {f.get('resource_type', 'cloud_run_service')}
  Ingress:            {f.get('ingress')}
  Unauthenticated:    {f.get('unauthenticated')}
  Default SA:         {f.get('is_default_sa')}
  Service Account:    {f.get('service_account', 'unknown')}
  Requests ({ld}d):   {f.get('request_count', 0)}
  Last Request:       {f.get('last_request_date', 'N/A')}
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
    return f"""
Scan Traffic Window:  {lookback_days} days
Total findings:       {summary.get('total', 0)}
Needs remediation:    {summary.get('needs_remediation', 0)}
Critical:             {summary.get('Critical', 0)}
High:                 {summary.get('High', 0)}
Medium:               {summary.get('Medium', 0)}
Low:                  {summary.get('Low', 0)}
Minimal:              {summary.get('Minimal', 0)}
"""


# ──────────────────────────────────────────────────────────────────────────────
# GEMINI: STRUCTURED ANALYSIS CALL
# ──────────────────────────────────────────────────────────────────────────────

def _call_gemini(
    findings: list[dict],
    summary: dict,
    project_scope: str,
    user_prompt: str,
    vertex_project: str,
) -> dict:
    """
    Single Gemini call per run. Returns a structured dict with:
      - executive_summary   : plain English summary (3–5 sentences)
      - smart_analysis      : list of pattern observations across findings
      - strategic_recs      : list of recommendations (project-team-actionable only)

    All risk classification, remediation commands, and service lists are
    pre-computed in Python — Gemini only narrates and analyses patterns.
    """
    risk_matrix = _load_risk_matrix()
    lookback = settings.TRAFFIC_LOOKBACK_DAYS
    if findings:
        lookback = findings[0].get("lookback_days", lookback)

    system_prompt = f"""You are a GCP Cloud Security Analyst producing structured analysis for a security report.

You receive pre-classified findings. Your job is:
1. Write a concise executive summary (3-5 sentences, plain English, non-technical audience)
2. Identify patterns across all findings and write smart analysis notes
3. Write strategic recommendations for the PROJECT TEAM ONLY

RISK MATRIX REFERENCE:
{risk_matrix}

STRICT RULES:
- Do NOT re-classify services — use risk_category and risk_level already provided
- Do NOT generate gcloud commands — remediation is pre-computed
- Do NOT recommend "Enforce Centralized Ingress Control" or "Automate Remediation" — these are handled by the central platform team, not the project team
- Always reference the actual traffic window ({lookback} days)
- Zero-traffic services should always be flagged for potential decommission
- If all services share the same issue, say so explicitly — one pattern is more useful than 40 repetitions
- Smart analysis: look for naming patterns, ingress consistency, traffic anomalies, SA issues

Respond ONLY with valid JSON. No markdown fences. No preamble. Example structure:
{{
  "executive_summary": "...",
  "smart_analysis": [
    "Pattern note 1",
    "Pattern note 2"
  ],
  "strategic_recs": [
    {{"title": "...", "description": "..."}},
    {{"title": "...", "description": "..."}}
  ]
}}"""

    user_message = f"""Analyse the following GCP security scan and return structured JSON.

USER REQUEST: {user_prompt}
SCOPE: {project_scope}
SCAN DATE: {datetime.now().strftime('%Y-%m-%d')}
TRAFFIC WINDOW: {lookback} days

SUMMARY:
{_build_summary_context(summary, lookback)}

CLASSIFIED FINDINGS:
{_build_findings_context(findings)}
"""

    client = genai.Client(
        vertexai=True,
        project=vertex_project,
        location=settings.VERTEX_AI_LOCATION,
    )

    logger.info(f"Calling Gemini {settings.GEMINI_MODEL} for structured analysis...")

    try:
        response = client.models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=user_message,
            config={"system_instruction": system_prompt},
        )
    except Exception as e:
        err = str(e)
        if "403" in err or "PERMISSION_DENIED" in err:
            raise PermissionError(
                f"\n\n❌ PERMISSION DENIED — Gemini call failed.\n"
                f"   Vertex AI project: {vertex_project}\n"
                f"   Missing role: roles/aiplatform.user\n\n"
                f"   Fix:\n"
                f"   gcloud projects add-iam-policy-binding {vertex_project} \\\n"
                f"     --member='user:YOUR_EMAIL' \\\n"
                f"     --role='roles/aiplatform.user'\n"
            ) from e
        elif "404" in err or "not exist" in err:
            raise RuntimeError(
                f"\n\n❌ MODEL NOT FOUND — {settings.GEMINI_MODEL} unavailable "
                f"in {settings.VERTEX_AI_LOCATION}.\n"
                f"   Check GEMINI_MODEL and VERTEX_AI_LOCATION in .env\n"
            ) from e
        else:
            raise RuntimeError(f"\n\n❌ Gemini API error — {err}\n") from e

    # Parse JSON response — strip accidental fences
    raw = response.text.strip()
    raw = re.sub(r"^```json\s*", "", raw)
    raw = re.sub(r"```$", "", raw.strip())

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Gemini returned non-JSON — using fallback analysis")
        return {
            "executive_summary": raw[:600] if raw else "Analysis unavailable.",
            "smart_analysis": [],
            "strategic_recs": [],
        }


# ──────────────────────────────────────────────────────────────────────────────
# HTML REPORT BUILDERS
# ──────────────────────────────────────────────────────────────────────────────

def _risk_badge_class(level: str) -> str:
    return {
        "Critical": "rb-critical",
        "High":     "rb-high",
        "Medium":   "rb-medium",
        "Low":      "rb-low",
        "Minimal":  "rb-minimal",
    }.get(level, "rb-minimal")


def _severity_order(level: str) -> int:
    return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Minimal": 4}.get(level, 5)


def _md_to_html(text: str) -> str:
    """
    Converts minimal Markdown from Gemini output into safe inline HTML.
    Handles: **bold** → <strong>, `code` → <code>
    Does NOT use a full Markdown parser — only targets patterns Gemini produces.
    """
    import re
    # **bold** → <strong>bold</strong>
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    # `code` → <code>code</code>
    text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
    return text



def _build_project_report_html(
    findings,
    summary,
    project_id,
    project_scope,
    analysis,
    scan_date,
    lookback,
):
    """
    Per-project HTML report with 4 standalone sections:
      01  What Was Found   - risk group cards, why-block, service chips
      02  How to Fix       - bash scripts grouped by risk category
      03  Review Required  - zero-traffic services (omitted if none)
      04  Recommendations  - Gemini strategic recs
      Appendix - full findings table
    """

    # ── helpers ---------------------------------------------------------------

    def chip(name, inactive):
        cls = "chip chip-warn" if inactive else "chip"
        sfx = " &#9888; 0 req" if inactive else ""
        return '<span class="' + cls + '">' + name + sfx + "</span>"

    def score_tile(cls, num, label):
        return (
            '<div class="score-tile t-' + cls + '">'
            + '<div class="score-num">' + str(num) + "</div>"
            + '<div class="score-label">' + label + "</div></div>"
        )

    def code_block(bid, title, tag_html, script):
        btn = '<button class="copy-btn" onclick="copyCode(\'' + bid + '\')">Copy</button>'
        pre = '<pre class="code-block" id="' + bid + '">' + script + "</pre>"
        meta = '<div class="code-meta"><span class="code-title">' + title + "</span>" + tag_html + "</div>"
        return '<div class="code-section">' + meta + '<div class="code-wrap">' + btn + pre + "</div></div>"

    def bash_cr(svc_list, proj, region, flag):
        svcs = "\n".join('  "' + s + '"' for s in svc_list)
        return "\n".join([
            "#!/bin/bash",
            'PROJECT="' + proj + '"',
            'REGION="' + region + '"',
            "SERVICES=(",
            svcs,
            ")",
            "",
            'for SVC in "${SERVICES[@]}"; do',
            '  echo "-> Updating $SVC ..."',
            '  gcloud run services update "$SVC" \\',
            "    --ingress " + flag + " \\",
            '    --region  "$REGION" \\',
            '    --project "$PROJECT"',
            "done",
            "",
            'echo "Done. Verify: GCP Console -> Cloud Run -> Networking tab"',
        ])

    def bash_cf(fn_list, proj, region, flag):
        fns = "\n".join('  "' + fn + '"' for fn in fn_list)
        return "\n".join([
            "#!/bin/bash",
            'PROJECT="' + proj + '"',
            'REGION="' + region + '"',
            "FUNCTIONS=(",
            fns,
            ")",
            "",
            'for FN in "${FUNCTIONS[@]}"; do',
            '  echo "-> Updating $FN ..."',
            '  gcloud functions deploy "$FN" \\',
            "    --ingress-settings " + flag + " \\",
            '    --region  "$REGION" \\',
            '    --project "$PROJECT"',
            "done",
        ])

    # ── group findings by risk_category --------------------------------------
    from collections import defaultdict
    groups = defaultdict(list)
    for f in findings:
        groups[f.get("risk_category", "Unknown")].append(f)

    sorted_groups = sorted(
        groups.items(),
        key=lambda kv: _severity_order(kv[1][0].get("risk_level", "Minimal"))
    )

    # ── scorecard ------------------------------------------------------------
    scorecard_html = (
        score_tile("critical", summary.get("Critical", 0), "&#9940; Critical")
        + score_tile("high",    summary.get("High",     0), "&#128308; High")
        + score_tile("medium",  summary.get("Medium",   0), "&#129000; Medium")
        + score_tile("low",     summary.get("Low",      0), "&#128309; Low")
        + score_tile("minimal", summary.get("Minimal",  0), "&#128994; Minimal")
    )

    # ── meta chips -----------------------------------------------------------
    regions   = sorted(set(f.get("region", "") for f in findings if f.get("region")))
    cr_count  = sum(1 for f in findings if f.get("resource_type") == "cloud_run_service")
    cf1_count = sum(1 for f in findings if f.get("resource_type") == "cloud_function_gen1")
    cf2_count = sum(1 for f in findings if f.get("resource_type") == "cloud_function_gen2")

    meta_parts = ["&#128197; " + scan_date, "&#128336; " + str(lookback) + "d window"]
    if cr_count:  meta_parts.append("&#128193; " + str(cr_count) + " Cloud Run")
    if cf1_count: meta_parts.append("&#9889; " + str(cf1_count) + " CF Gen1 &#9888;")
    if cf2_count: meta_parts.append("&#9889; " + str(cf2_count) + " CF Gen2")
    if regions:   meta_parts.append("&#128205; " + ", ".join(regions))
    meta_chips = "".join('<span class="meta-chip">' + p + "</span>" for p in meta_parts)

    # ── overall badge --------------------------------------------------------
    overall_level = "Minimal"
    for lvl in ["Critical", "High", "Medium", "Low"]:
        if summary.get(lvl, 0) > 0:
            overall_level = lvl
            break
    icon_map = {
        "Critical": "&#9940;", "High": "&#128308;",
        "Medium":   "&#9888;", "Low":  "&#128309;", "Minimal": "&#9989;"
    }
    badge_lbl = (
        "Action Required" if overall_level in ("Critical", "High", "Medium")
        else "Review" if overall_level == "Low" else "Clean"
    )
    overall_html = (
        '<div class="overall-badge badge-' + overall_level.lower() + '-hero">'
        + icon_map.get(overall_level, "") + " " + badge_lbl + "</div>"
    )

    # ── insight bar ----------------------------------------------------------
    exec_summary = _md_to_html(analysis.get("executive_summary", ""))
    insight_html = (
        '<div class="insight-bar"><div class="insight-icon">&#128161;</div>'
        + '<div class="insight-text">' + exec_summary + "</div></div>"
    ) if exec_summary else ""

    # ── Smart Analysis — built ONCE from all notes, rendered as standalone section
    raw_notes = list(analysis.get("smart_analysis", []))
    if raw_notes:
        notes_html = "".join(
            "<div>&bull; " + _md_to_html(n) + "</div>" for n in raw_notes
        )
        smart_analysis_html = (
            '<div class="smart-note">'
            '<div class="note-label">&#129504; Smart Analysis</div>'
            + notes_html + "</div>"
        )
    else:
        smart_analysis_html = ""

    # ── one pass over sorted_groups ------------------------------------------
    all_zero_traffic = []
    all_scripts      = []
    sec01_html       = ""
    group_idx        = 0

    for cat, grp in sorted_groups:
        group_idx += 1
        level = grp[0].get("risk_level", "Minimal")
        bc    = _risk_badge_class(level)
        gid   = "rg-" + str(group_idx)

        zero = [f for f in grp if f.get("request_count", 0) == 0]
        all_zero_traffic.extend(zero)

        # why block
        dims    = grp[0].get("triggered_dimensions", [])
        auth_ok = not grp[0].get("unauthenticated")
        sa_ok   = not grp[0].get("is_default_sa")
        why_html = (
            "<strong>What this means:</strong> " + ", ".join(dims) + "<br><br>"
            + "<strong>What&#39;s already good:</strong> "
            + ("&#9989; IAM authentication enforced" if auth_ok else "&#10060; Unauthenticated access enabled")
            + (" &nbsp;&middot;&nbsp; &#9989; Custom service accounts"
               if sa_ok else " &nbsp;&middot;&nbsp; &#9888; Default SA in use")
        )

        chips_html  = "".join(chip(f["name"], f.get("request_count", 0) == 0) for f in grp)
        chips_count = len(grp)

        # Section 01 card — chips only, no scripts
        toggle     = (
            '<div class="chips-toggle" onclick="toggleChips(\'chips-' + gid + '\', this)">'
            "&#9658; Show all " + str(chips_count) + " affected resources</div>"
        )
        chips_wrap = (
            '<div class="chips-wrap" id="chips-' + gid + '" style="display:none">'
            + chips_html + "</div>"
        )
        rg_head = (
            '<div class="rg-head" onclick="toggleRG(\'' + gid + '\')">'
            + '<span class="risk-badge ' + bc + '">' + level + "</span>"
            + '<span class="rg-title">' + cat + "</span>"
            + '<span class="rg-count">' + str(chips_count) + " resource(s)</span>"
            + '<span class="chevron open" id="' + gid + '-chev">&#9658;</span>'
            + "</div>"
        )
        rg_body = (
            '<div class="rg-body open" id="' + gid + '-body">'
            + '<div class="why-block">' + why_html + "</div>"
            + toggle + chips_wrap
            + "</div>"
        )
        sec01_html += '<div class="risk-group" id="' + gid + '">' + rg_head + rg_body + "</div>"

        # Collect Section 02 scripts (active resources only)
        proj_val   = grp[0].get("project_id", "")
        region_val = grp[0].get("region", "")
        cr_fix = [f["name"] for f in grp
                  if f.get("resource_type") == "cloud_run_service"
                  and f.get("request_count", 0) > 0]
        cf_fix = [f["name"] for f in grp
                  if f.get("resource_type") in ("cloud_function_gen1", "cloud_function_gen2")
                  and f.get("request_count", 0) > 0]

        grp_scripts = ""
        if cr_fix:
            option_guide = (
                '<div class="smart-note" style="margin-bottom:16px">'
                '<div class="note-label">&#128161; Which option should I use?</div>'
                "<strong>Option A &mdash; <code>internal</code></strong> &mdash; "
                "if services are only called from within GCP "
                "(Cloud Scheduler, Pub/Sub, another Cloud Run service). Best for internal pipelines.<br><br>"
                "<strong>Option B &mdash; <code>internal-and-cloud-load-balancing</code></strong> &mdash; "
                "if services must be reachable via a Load Balancer from outside the VPC. Use this if unsure."
                "</div>"
            )
            grp_scripts += option_guide
            grp_scripts += code_block(
                "script-a-" + gid,
                "Option A &mdash; ingress=internal",
                '<span class="code-tag tag-internal">&#9989; Most restrictive</span>',
                bash_cr(cr_fix, proj_val, region_val, "internal"),
            )
            grp_scripts += code_block(
                "script-b-" + gid,
                "Option B &mdash; ingress=internal-and-cloud-load-balancing",
                '<span class="code-tag tag-lb">&#128309; Safer if unsure</span>',
                bash_cr(cr_fix, proj_val, region_val, "internal-and-cloud-load-balancing"),
            )

        if cf_fix:
            grp_scripts += code_block(
                "script-cf-" + gid,
                "Cloud Functions (" + cat + ") &mdash; ingress=internal-and-gclb",
                "",
                bash_cf(cf_fix, proj_val, region_val, "internal-and-gclb"),
            )

        if grp_scripts:
            all_scripts.append((cat, level, bc, grp_scripts))

    # ── Section 02: How to Fix -----------------------------------------------
    sec02_html = ""
    if all_scripts:
        sec02_html = (
            '<p style="font-size:14px;color:var(--dim);margin-bottom:18px">'
            '<strong style="color:var(--txt)">&#9888; Before running:</strong> '
            "These scripts make live changes. Run one service manually first to validate, "
            "then run the full loop. Zero-traffic services are excluded &mdash; "
            "review them in Section 03.</p>"
        )
        for cat, level, bc, grp_scripts in all_scripts:
            label_bar = (
                '<div style="margin-bottom:8px;display:flex;align-items:center;gap:10px;'
                'padding-bottom:8px;border-bottom:1px solid var(--bdr)">'
                + '<span class="risk-badge ' + bc + '" style="font-size:11px">' + level + "</span>"
                + '<span style="font-size:14px;font-weight:500">' + cat + "</span></div>"
            )
            sec02_html += label_bar + grp_scripts + '<div style="margin-bottom:28px"></div>'

    # ── Section 03: Review Required ------------------------------------------
    sec03_html = ""
    tl_map = {
        "cloud_run_service":   "Cloud Run Service",
        "cloud_function_gen1": "Cloud Function Gen1",
        "cloud_function_gen2": "Cloud Function Gen2",
    }
    for f in all_zero_traffic:
        rtype      = f.get("resource_type", "cloud_run_service")
        type_label = tl_map.get(rtype, rtype)
        pid        = f.get("project_id", "")
        region     = f.get("region", "")
        name       = f.get("name", "")
        safe_id    = name.replace(".", "-").replace("_", "-")
        bc_z       = _risk_badge_class(f.get("risk_level", "Minimal"))

        if rtype == "cloud_run_service":
            del_cmd = "gcloud run services delete " + name + " --region " + region + " --project " + pid
        else:
            del_cmd = "gcloud functions delete " + name + " --region " + region + " --project " + pid

        badge = (
            '<span class="risk-badge ' + bc_z + '" style="font-size:10px">'
            + f.get("risk_level", "") + "</span>"
        )
        desc = (
            type_label + " &nbsp;&middot;&nbsp; " + region
            + ' &nbsp;&middot;&nbsp; <strong style="color:var(--medium)">0 requests ('
            + str(lookback) + "d)</strong><br>"
            "Confirm with your team whether this service is still in use. "
            "If not, delete it to reduce attack surface and cloud cost."
        )
        sec03_html += (
            '<div class="review-card">'
            + '<div class="rv-icon">&#128376;</div>'
            + '<div style="flex:1">'
            + '<div class="rv-name">' + name + " &nbsp;" + badge + "</div>"
            + '<div class="rv-desc">' + desc + "</div>"
            + '<div style="margin-top:10px">'
            + code_block("del-" + safe_id, "Delete command &mdash; review before running", "", del_cmd)
            + "</div></div></div>"
        )

    # ── Recommendations ------------------------------------------------------
    recs_html = ""
    for i, rec in enumerate(analysis.get("strategic_recs", []), 1):
        recs_html += (
            '<div class="rec-item">'
            + '<div class="rec-n">' + str(i) + "</div><div>"
            + '<div class="rec-title">' + rec.get("title", "") + "</div>"
            + '<div class="rec-desc">' + rec.get("description", "") + "</div>"
            + "</div></div>"
        )

    # ── Full findings table --------------------------------------------------
    tl_short = {
        "cloud_run_service":   "CR",
        "cloud_function_gen1": "CF Gen1",
        "cloud_function_gen2": "CF Gen2",
    }
    table_rows = ""
    for f in sorted(findings, key=lambda x: _severity_order(x.get("risk_level", "Minimal"))):
        zero       = f.get("request_count", 0) == 0
        rtype      = f.get("resource_type", "cloud_run_service")
        tl         = tl_short.get(rtype, rtype)
        type_cls   = "type-cr" if rtype == "cloud_run_service" else "type-cf2"
        warn_tag   = '<span class="warn-tag">&#9888; 0 req</span>' if zero else ""
        bc_t       = _risk_badge_class(f.get("risk_level", "Minimal"))
        auth_color = "var(--critical)" if f.get("unauthenticated") else "var(--minimal)"
        auth_label = "&#10060; Open" if f.get("unauthenticated") else "&#9989; Required"
        row_style  = "color:var(--medium)" if zero else ""
        table_rows += (
            "<tr>"
            + '<td class="svc-name">' + f.get("name", "") + warn_tag + "</td>"
            + '<td><span class="type-pill ' + type_cls + '">' + tl + "</span></td>"
            + "<td>" + f.get("region", "") + "</td>"
            + '<td><span class="ingress-all">' + f.get("ingress", "") + "</span></td>"
            + '<td style="color:' + auth_color + '">' + auth_label + "</td>"
            + '<td style="' + row_style + '">' + str(f.get("request_count", 0)) + "</td>"
            + '<td><span class="risk-badge ' + bc_t + '" style="font-size:11px">'
            + f.get("risk_level", "") + "</span></td>"
            + "</tr>"
        )

    sec03_count = len(all_zero_traffic)

    return _render_project_template(
        project_id=project_id,
        scan_date=scan_date,
        lookback=lookback,
        total=summary.get("total", 0),
        meta_chips=meta_chips,
        overall_html=overall_html,
        scorecard_html=scorecard_html,
        insight_html=insight_html,
        smart_analysis_html=smart_analysis_html,
        sec01_groups_html=sec01_html,
        sec02_html=sec02_html,
        sec03_html=sec03_html,
        sec03_count=sec03_count,
        recs_html=recs_html,
        table_rows=table_rows,
    )

def _render_project_template(**ctx) -> str:
    """Returns inline HTML — no external template file required."""
    p = ctx
    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Report — {p['project_id']}</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{{--t:background .25s,color .25s,border-color .25s;}}
[data-theme=light]{{--bg:#f5f6f8;--sur:#fff;--sur2:#f0f2f5;--bdr:#e2e5eb;--txt:#111827;--dim:#4b5563;--mut:#9ca3af;--cbg:#f8f9fb;--shd:0 1px 4px rgba(0,0,0,.07),0 4px 16px rgba(0,0,0,.04);}}
[data-theme=dark]{{--bg:#0f1117;--sur:#181c27;--sur2:#1e2333;--bdr:#2a2f42;--txt:#e2e8f0;--dim:#8892a4;--mut:#4a5568;--cbg:#0a0d14;--shd:none;}}
*{{box-sizing:border-box;margin:0;padding:0;}}
html{{scroll-behavior:smooth;}}
body{{font-family:'DM Sans',sans-serif;background:var(--bg);color:var(--txt);font-size:15px;line-height:1.6;transition:var(--t);}}
.header{{background:var(--sur);border-bottom:1px solid var(--bdr);padding:0 40px;height:60px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:200;box-shadow:var(--shd);transition:var(--t);}}
.hl{{display:flex;align-items:center;gap:14px;}}
.logo{{width:32px;height:32px;background:linear-gradient(135deg,#4f46e5,#7c3aed);border-radius:7px;display:flex;align-items:center;justify-content:center;font-size:16px;}}
.an{{font-size:13px;font-weight:600;}}.as{{font-size:12px;color:var(--mut);font-family:'DM Mono',monospace;}}
.hr2{{display:flex;align-items:center;gap:10px;}}
.hpill{{font-size:12px;font-family:'DM Mono',monospace;background:var(--sur2);border:1px solid var(--bdr);padding:4px 10px;border-radius:20px;color:var(--dim);transition:var(--t);}}
.tt{{width:44px;height:24px;background:var(--bdr);border-radius:12px;position:relative;cursor:pointer;border:none;transition:background .25s;flex-shrink:0;}}
.tt::after{{content:'';width:18px;height:18px;background:var(--sur);border-radius:50%;position:absolute;top:3px;left:3px;transition:transform .25s;box-shadow:0 1px 3px rgba(0,0,0,.2);}}
[data-theme=dark] .tt::after{{transform:translateX(20px);}}[data-theme=dark] .tt{{background:#4f46e5;}}
.tl{{font-size:12px;color:var(--mut);}}
.container{{max-width:1060px;margin:0 auto;padding:32px 40px 60px;}}
.pbanner{{background:var(--sur);border:1px solid var(--bdr);border-radius:12px;padding:24px 28px;margin-bottom:22px;display:flex;align-items:center;justify-content:space-between;box-shadow:var(--shd);transition:var(--t);}}
.pid{{font-family:'DM Mono',monospace;font-size:24px;font-weight:500;letter-spacing:-.5px;}}
.pmeta{{display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;}}
.meta-chip{{font-size:12px;font-family:'DM Mono',monospace;background:var(--sur2);border:1px solid var(--bdr);padding:3px 10px;border-radius:20px;color:var(--dim);transition:var(--t);}}
.overall-badge{{font-size:13px;font-weight:600;padding:8px 20px;border-radius:8px;font-family:'DM Mono',monospace;white-space:nowrap;}}
.badge-critical-hero{{background:rgba(220,38,38,.1);color:#dc2626;border:1px solid rgba(220,38,38,.25);}}
.badge-high-hero{{background:rgba(234,88,12,.1);color:#ea580c;border:1px solid rgba(234,88,12,.25);}}
.badge-medium-hero{{background:rgba(217,119,6,.1);color:#d97706;border:1px solid rgba(217,119,6,.25);}}
.badge-low-hero{{background:rgba(37,99,235,.1);color:#2563eb;border:1px solid rgba(37,99,235,.25);}}
.badge-minimal-hero{{background:rgba(5,150,105,.08);color:#059669;border:1px solid rgba(5,150,105,.2);}}
.scorecard{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:20px;}}
.score-tile{{background:var(--sur);border:1px solid var(--bdr);border-radius:10px;padding:16px 20px;position:relative;overflow:hidden;box-shadow:var(--shd);transition:var(--t);}}
.score-tile::after{{content:'';position:absolute;top:0;left:0;right:0;height:3px;border-radius:10px 10px 0 0;}}
.t-critical::after{{background:#dc2626;}}.t-high::after{{background:#ea580c;}}.t-medium::after{{background:#d97706;}}.t-low::after{{background:#2563eb;}}.t-minimal::after{{background:#059669;}}
.score-num{{font-family:'DM Mono',monospace;font-size:30px;font-weight:500;line-height:1;}}
.t-critical .score-num{{color:#dc2626;}}.t-high .score-num{{color:#ea580c;}}.t-medium .score-num{{color:#d97706;}}.t-low .score-num{{color:#2563eb;}}.t-minimal .score-num{{color:#059669;}}
.score-label{{font-size:11px;color:var(--mut);margin-top:5px;text-transform:uppercase;letter-spacing:.5px;}}
.insight-bar{{background:var(--sur);border:1px solid var(--bdr);border-left:3px solid #d97706;border-radius:10px;padding:16px 20px;margin-bottom:28px;display:flex;gap:12px;box-shadow:var(--shd);transition:var(--t);}}
.insight-icon{{font-size:18px;flex-shrink:0;margin-top:1px;}}.insight-text{{font-size:15px;line-height:1.8;color:var(--dim);}}
.insight-text strong{{color:var(--txt);}}
code{{font-family:'DM Mono',monospace;font-size:13px;background:var(--sur2);padding:1px 5px;border-radius:4px;border:1px solid var(--bdr);}}
.section{{margin-bottom:36px;}}
.section-header{{display:flex;align-items:center;gap:10px;margin-bottom:14px;padding-bottom:12px;border-bottom:1px solid var(--bdr);}}
.sec-num{{font-family:'DM Mono',monospace;font-size:11px;color:#4f46e5;background:rgba(79,70,229,.08);border:1px solid rgba(79,70,229,.18);padding:2px 8px;border-radius:4px;}}
.sec-title{{font-size:16px;font-weight:600;}}.sec-count{{margin-left:auto;font-family:'DM Mono',monospace;font-size:12px;color:var(--mut);}}
.risk-group{{background:var(--sur);border:1px solid var(--bdr);border-radius:10px;margin-bottom:14px;overflow:hidden;box-shadow:var(--shd);transition:var(--t);}}
.rg-head{{padding:14px 20px;display:flex;align-items:center;gap:10px;cursor:pointer;user-select:none;transition:background .15s;}}
.rg-head:hover{{background:var(--sur2);}}
.rg-body{{display:none;padding:4px 20px 20px;}}
.rg-body.open{{display:block;}}
.risk-badge{{font-family:'DM Mono',monospace;font-size:11px;font-weight:500;padding:3px 9px;border-radius:4px;text-transform:uppercase;letter-spacing:.4px;flex-shrink:0;}}
.rb-critical{{background:rgba(220,38,38,.1);color:#dc2626;border:1px solid rgba(220,38,38,.25);}}
.rb-high{{background:rgba(234,88,12,.1);color:#ea580c;border:1px solid rgba(234,88,12,.25);}}
.rb-medium{{background:rgba(217,119,6,.1);color:#d97706;border:1px solid rgba(217,119,6,.25);}}
.rb-low{{background:rgba(37,99,235,.1);color:#2563eb;border:1px solid rgba(37,99,235,.25);}}
.rb-minimal{{background:rgba(5,150,105,.08);color:#059669;border:1px solid rgba(5,150,105,.2);}}
.rg-title{{font-size:15px;font-weight:500;flex:1;}}.rg-count{{font-family:'DM Mono',monospace;font-size:13px;color:var(--mut);}}
.chevron{{color:var(--mut);font-size:10px;transition:transform .2s;flex-shrink:0;}}.chevron.open{{transform:rotate(90deg);}}
.why-block{{background:var(--sur2);border:1px solid var(--bdr);border-radius:8px;padding:14px 16px;margin-bottom:12px;font-size:15px;line-height:1.8;color:var(--dim);transition:var(--t);}}
.why-block strong{{color:var(--txt);}}
.smart-note{{background:rgba(79,70,229,.05);border:1px solid rgba(79,70,229,.18);border-radius:8px;padding:12px 16px;margin-bottom:12px;font-size:15px;line-height:1.65;}}
[data-theme=dark] .smart-note{{background:rgba(79,70,229,.08);}}
.note-label{{font-family:'DM Mono',monospace;font-size:11px;font-weight:500;color:#4f46e5;text-transform:uppercase;letter-spacing:.5px;margin-bottom:5px;}}
.warn-note{{background:rgba(217,119,6,.05);border:1px solid rgba(217,119,6,.2);border-radius:8px;padding:12px 16px;margin-bottom:12px;font-size:14px;line-height:1.65;}}
[data-theme=dark] .warn-note{{background:rgba(217,119,6,.07);}}
.warn-label{{font-family:'DM Mono',monospace;font-size:11px;font-weight:500;color:#d97706;text-transform:uppercase;letter-spacing:.5px;margin-bottom:5px;}}
.chips-toggle{{font-size:14px;color:#4f46e5;cursor:pointer;display:inline-flex;align-items:center;gap:5px;margin-bottom:10px;font-family:'DM Mono',monospace;user-select:none;}}
.chips-toggle:hover{{text-decoration:underline;}}
.chips-wrap{{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px;}}
.chip{{font-family:'DM Mono',monospace;font-size:13px;background:var(--sur2);border:1px solid var(--bdr);padding:3px 9px;border-radius:4px;color:var(--dim);transition:var(--t);}}
.chip-warn{{border-color:rgba(217,119,6,.35);color:#d97706;}}
[data-theme=dark] .chip-warn{{color:#fbbf24;}}
.code-section{{margin-bottom:20px;}}
.code-meta{{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;}}
.code-title{{font-family:'DM Mono',monospace;font-size:12px;color:var(--dim);font-weight:500;}}
.code-tag{{font-family:'DM Mono',monospace;font-size:11px;padding:2px 8px;border-radius:4px;}}
.tag-internal{{background:rgba(5,150,105,.1);color:#059669;border:1px solid rgba(5,150,105,.2);}}
.tag-lb{{background:rgba(37,99,235,.1);color:#2563eb;border:1px solid rgba(37,99,235,.2);}}
.tag-warn{{background:rgba(217,119,6,.1);color:#d97706;border:1px solid rgba(217,119,6,.2);}}
.code-wrap{{position:relative;}}
.code-block{{background:var(--cbg);border:1px solid var(--bdr);border-radius:8px;padding:16px;overflow-x:auto;font-family:'DM Mono',monospace;font-size:13px;line-height:1.8;color:var(--dim);white-space:pre;transition:var(--t);}}
.copy-btn{{position:absolute;top:8px;right:8px;background:var(--sur2);border:1px solid var(--bdr);color:var(--dim);font-family:'DM Mono',monospace;font-size:12px;padding:4px 10px;border-radius:5px;cursor:pointer;transition:all .15s;}}
.copy-btn:hover{{background:var(--sur);color:var(--txt);}}.copy-btn.ok{{color:#059669;border-color:#059669;}}
.rec-item{{background:var(--sur);border:1px solid var(--bdr);border-radius:8px;padding:16px 20px;margin-bottom:10px;display:flex;gap:14px;box-shadow:var(--shd);transition:var(--t);}}
.rec-n{{font-family:'DM Mono',monospace;font-size:12px;color:#4f46e5;background:rgba(79,70,229,.08);border:1px solid rgba(79,70,229,.18);width:28px;height:28px;border-radius:5px;display:flex;align-items:center;justify-content:center;flex-shrink:0;}}
.rec-title{{font-size:14px;font-weight:500;margin-bottom:4px;}}.rec-desc{{font-size:14px;color:var(--dim);line-height:1.65;}}
.tbl-wrap{{overflow-x:auto;border-radius:8px;border:1px solid var(--bdr);}}
table{{width:100%;border-collapse:collapse;font-size:13px;font-family:'DM Mono',monospace;}}
thead tr{{background:var(--sur2);}}
th{{padding:10px 14px;text-align:left;font-size:11px;font-weight:500;color:var(--mut);text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--bdr);}}
td{{padding:9px 14px;border-bottom:1px solid var(--bdr);color:var(--dim);vertical-align:middle;transition:var(--t);}}
tbody tr:last-child td{{border-bottom:none;}}tbody tr:hover td{{background:var(--sur2);}}
td.svc-name{{color:var(--txt);font-weight:500;}}
.warn-tag{{font-size:11px;background:rgba(217,119,6,.1);border:1px solid rgba(217,119,6,.2);color:#d97706;padding:1px 5px;border-radius:3px;margin-left:6px;}}
.type-cr{{background:rgba(79,70,229,.08);color:#4f46e5;border:1px solid rgba(79,70,229,.18);}}
.type-cf2{{background:rgba(5,150,105,.08);color:#059669;border:1px solid rgba(5,150,105,.18);}}
.type-pill{{font-size:11px;padding:2px 6px;border-radius:3px;}}
.ingress-all{{color:#d97706;font-family:'DM Mono',monospace;font-size:12px;}}
hr{{border:none;border-top:1px solid var(--bdr);margin:32px 0;}}
.footer{{text-align:center;padding:20px 40px;border-top:1px solid var(--bdr);color:var(--mut);font-size:12px;font-family:'DM Mono',monospace;}}
.footer a{{color:#4f46e5;text-decoration:none;}}.footer a:hover{{text-decoration:underline;}}
::-webkit-scrollbar{{width:5px;height:5px;}}::-webkit-scrollbar-track{{background:transparent;}}::-webkit-scrollbar-thumb{{background:var(--bdr);border-radius:3px;}}
</style>
</head>
<body>
<div class="header">
  <div class="hl">
    <div class="logo">🔍</div>
    <div><div class="an">GCP Security Agent</div></div>
  </div>
  <div class="hr2">
    <span class="hpill">📅 {p['scan_date']}</span>
    <span class="hpill">🕐 {p['lookback']}d window</span>
    <span class="hpill">{p['total']} findings</span>
    <span class="tl" id="tl">🌙</span>
    <button class="tt" onclick="toggleTheme()" aria-label="Toggle theme"></button>
  </div>
</div>
<div class="container">
  <div class="pbanner">
    <div>
      <div class="pid">{p['project_id']}</div>
      <div class="pmeta">{p['meta_chips']}</div>
    </div>
    {p['overall_html']}
  </div>
  <div class="scorecard">{p['scorecard_html']}</div>
  {p['insight_html']}

  {('<div class="section"><div class="section-header"><span class="sec-num">&#129504;</span><span class="sec-title">Smart Analysis</span></div>' + p['smart_analysis_html'] + '</div>') if p['smart_analysis_html'] else ''}

  <div class="section">
    <div class="section-header">
      <span class="sec-num">01</span>
      <span class="sec-title">What Was Found</span>
      <span class="sec-count">{p['total']} resources</span>
    </div>
    {p['sec01_groups_html']}
  </div>

  <div class="section">
    <div class="section-header">
      <span class="sec-num">02</span>
      <span class="sec-title">How to Fix</span>
      <span class="sec-count">Ready-to-run bash scripts</span>
    </div>
    {p['sec02_html'] if p['sec02_html'] else '<p style="color:var(--mut);font-size:14px">No remediation scripts required — all resources already have correct ingress settings.</p>'}
  </div>

  {'<div class="section"><div class="section-header"><span class="sec-num">03</span><span class="sec-title">Review Required — Possible Legacy Services</span><span class="sec-count">' + str(p['sec03_count']) + ' resource(s) · 0 requests in ' + str(p['lookback']) + ' days</span></div>' + p['sec03_html'] + '</div>' if p['sec03_count'] > 0 else ''}

  <div class="section">
    <div class="section-header">
      <span class="sec-num">{'04' if p['sec03_count'] > 0 else '03'}</span>
      <span class="sec-title">Recommendations for Your Team</span>
    </div>
    {p['recs_html'] if p['recs_html'] else '<p style="color:var(--mut);font-size:14px">No additional recommendations.</p>'}
  </div>

  <hr>

  <div class="section">
    <div class="section-header">
      <span class="sec-num">{'05' if p['sec03_count'] > 0 else '04'}</span>
      <span class="sec-title">Full Findings — Appendix</span>
      <span class="sec-count">{p['total']} resources</span>
    </div>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>Service / Function</th><th>Type</th><th>Region</th><th>Ingress</th><th>Auth</th><th>Requests ({p['lookback']}d)</th><th>Risk</th></tr></thead>
        <tbody>{p['table_rows']}</tbody>
      </table>
    </div>
  </div>
</div>
<div class="footer">
  GCP Security Agent &nbsp;·&nbsp; All remediation scripts are for human review only.
</div>
</div>
<script>
function toggleTheme(){{const h=document.documentElement,l=document.getElementById('tl');if(h.getAttribute('data-theme')==='dark'){{h.setAttribute('data-theme','light');l.textContent='☀️';}}else{{h.setAttribute('data-theme','dark');l.textContent='🌙';}}}}
function toggleRG(id){{const b=document.getElementById(id+'-body'),c=document.getElementById(id+'-chev');const o=b.classList.toggle('open');c.classList.toggle('open',o);}}
function toggleChips(id,el){{const w=document.getElementById(id);if(w.style.display==='none'){{w.style.display='flex';el.textContent='▼ Hide';}}else{{w.style.display='none';el.textContent='▶ Show all';}}}}
function copyCode(id){{const el=document.getElementById(id);navigator.clipboard.writeText(el.innerText).then(()=>{{const b=el.closest('.code-wrap').querySelector('.copy-btn');b.textContent='✓ Copied';b.classList.add('ok');setTimeout(()=>{{b.textContent='Copy';b.classList.remove('ok');}},2200);}});}}
</script>
</body></html>"""


# ──────────────────────────────────────────────────────────────────────────────
# ORG / FOLDER SUMMARY HTML
# ──────────────────────────────────────────────────────────────────────────────

def _build_org_summary_html(
    project_results: list[dict],
    scope_label: str,
    scan_date: str,
    lookback: int,
) -> str:
    """
    Builds org/folder summary dashboard HTML.
    project_results: list of dicts with keys:
      project_id, worst, critical, high, medium, low, total_findings, total_resources, report_file
    """

    rows_js = json.dumps(project_results, indent=2)

    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Summary — {scope_label}</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{{--t:background .25s,color .25s,border-color .25s;}}
[data-theme=light]{{--bg:#f5f6f8;--sur:#fff;--sur2:#f0f2f5;--bdr:#e2e5eb;--txt:#111827;--dim:#4b5563;--mut:#9ca3af;--shd:0 1px 4px rgba(0,0,0,.07),0 4px 16px rgba(0,0,0,.04);}}
[data-theme=dark]{{--bg:#0f1117;--sur:#181c27;--sur2:#1e2333;--bdr:#2a2f42;--txt:#e2e8f0;--dim:#8892a4;--mut:#4a5568;--shd:none;}}
*{{box-sizing:border-box;margin:0;padding:0;}}html{{scroll-behavior:smooth;}}
body{{font-family:'DM Sans',sans-serif;background:var(--bg);color:var(--txt);font-size:15px;line-height:1.6;transition:var(--t);}}
.header{{background:var(--sur);border-bottom:1px solid var(--bdr);padding:0 40px;height:60px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:200;box-shadow:var(--shd);transition:var(--t);}}
.hl{{display:flex;align-items:center;gap:14px;}}.logo{{width:32px;height:32px;background:linear-gradient(135deg,#4f46e5,#7c3aed);border-radius:7px;display:flex;align-items:center;justify-content:center;font-size:16px;}}
.an{{font-size:13px;font-weight:600;}}.as{{font-size:12px;color:var(--mut);font-family:'DM Mono',monospace;}}
.hr2{{display:flex;align-items:center;gap:10px;}}
.hpill{{font-size:12px;font-family:'DM Mono',monospace;background:var(--sur2);border:1px solid var(--bdr);padding:4px 10px;border-radius:20px;color:var(--dim);transition:var(--t);}}
.tt{{width:44px;height:24px;background:var(--bdr);border-radius:12px;position:relative;cursor:pointer;border:none;transition:background .25s;flex-shrink:0;}}
.tt::after{{content:'';width:18px;height:18px;background:var(--sur);border-radius:50%;position:absolute;top:3px;left:3px;transition:transform .25s;box-shadow:0 1px 3px rgba(0,0,0,.2);}}
[data-theme=dark] .tt::after{{transform:translateX(20px);}}[data-theme=dark] .tt{{background:#4f46e5;}}
.tl{{font-size:12px;color:var(--mut);}}
.container{{max-width:1100px;margin:0 auto;padding:32px 40px 60px;}}
.obanner{{background:var(--sur);border:1px solid var(--bdr);border-radius:12px;padding:24px 28px;margin-bottom:22px;box-shadow:var(--shd);transition:var(--t);}}
.otitle{{font-size:12px;color:var(--mut);font-family:'DM Mono',monospace;margin-bottom:4px;}}
.oid{{font-family:'DM Mono',monospace;font-size:20px;font-weight:500;letter-spacing:-.5px;}}
.ometa{{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap;}}
.omchip{{font-size:12px;font-family:'DM Mono',monospace;background:var(--sur2);border:1px solid var(--bdr);padding:3px 10px;border-radius:20px;color:var(--dim);transition:var(--t);}}
.osc{{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:22px;}}
.osc-tile{{background:var(--sur);border:1px solid var(--bdr);border-radius:10px;padding:14px 16px;position:relative;overflow:hidden;box-shadow:var(--shd);transition:var(--t);}}
.osc-tile::after{{content:'';position:absolute;top:0;left:0;right:0;height:3px;border-radius:10px 10px 0 0;}}
.t-critical::after{{background:#dc2626;}}.t-high::after{{background:#ea580c;}}.t-medium::after{{background:#d97706;}}.t-low::after{{background:#2563eb;}}.t-minimal::after{{background:#059669;}}.t-clean::after{{background:#6b7280;}}
.osc-num{{font-family:'DM Mono',monospace;font-size:24px;font-weight:500;line-height:1;}}
.t-critical .osc-num{{color:#dc2626;}}.t-high .osc-num{{color:#ea580c;}}.t-medium .osc-num{{color:#d97706;}}.t-low .osc-num{{color:#2563eb;}}.t-minimal .osc-num{{color:#059669;}}.t-clean .osc-num{{color:#6b7280;}}
.osc-label{{font-size:11px;color:var(--mut);margin-top:4px;text-transform:uppercase;letter-spacing:.5px;}}
.fbar{{display:flex;gap:10px;margin-bottom:18px;align-items:center;flex-wrap:wrap;}}
.sw{{flex:1;min-width:200px;position:relative;}}
.si{{width:100%;padding:8px 12px 8px 34px;background:var(--sur);border:1px solid var(--bdr);border-radius:8px;font-family:'DM Sans',sans-serif;font-size:14px;color:var(--txt);outline:none;transition:var(--t);}}
.si:focus{{border-color:#4f46e5;box-shadow:0 0 0 2px rgba(79,70,229,.15);}}
.sico{{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--mut);font-size:14px;pointer-events:none;}}
.fb{{padding:7px 14px;border-radius:8px;border:1px solid var(--bdr);background:var(--sur);color:var(--dim);font-size:13px;font-family:'DM Mono',monospace;cursor:pointer;transition:all .15s;}}
.fb:hover{{border-color:#4f46e5;color:#4f46e5;}}.fb.active{{background:rgba(79,70,229,.08);border-color:#4f46e5;color:#4f46e5;}}
.rc{{font-size:13px;color:var(--mut);font-family:'DM Mono',monospace;white-space:nowrap;}}
.ptw{{background:var(--sur);border:1px solid var(--bdr);border-radius:10px;overflow:hidden;box-shadow:var(--shd);transition:var(--t);}}
.pt{{width:100%;border-collapse:collapse;}}
.pt thead tr{{background:var(--sur2);}}
.pt th{{padding:10px 16px;text-align:left;font-size:11px;font-weight:500;color:var(--mut);text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--bdr);font-family:'DM Mono',monospace;}}
.pt td{{padding:12px 16px;border-bottom:1px solid var(--bdr);color:var(--dim);vertical-align:middle;transition:var(--t);}}
.pt tbody tr:last-child td{{border-bottom:none;}}.pt tbody tr:hover td{{background:var(--sur2);}}
td.pid2{{font-family:'DM Mono',monospace;font-size:14px;font-weight:500;color:var(--txt);}}
.sb{{display:inline-block;font-family:'DM Mono',monospace;font-size:11px;font-weight:500;padding:3px 9px;border-radius:4px;}}
.sb-critical{{background:rgba(220,38,38,.1);color:#dc2626;border:1px solid rgba(220,38,38,.25);}}
.sb-high{{background:rgba(234,88,12,.1);color:#ea580c;border:1px solid rgba(234,88,12,.25);}}
.sb-medium{{background:rgba(217,119,6,.1);color:#d97706;border:1px solid rgba(217,119,6,.25);}}
.sb-low{{background:rgba(37,99,235,.1);color:#2563eb;border:1px solid rgba(37,99,235,.25);}}
.sb-clean{{background:rgba(5,150,105,.08);color:#059669;border:1px solid rgba(5,150,105,.2);}}
.sv{{display:flex;gap:3px;align-items:center;flex-wrap:wrap;}}
.sd{{display:inline-flex;align-items:center;gap:4px;font-family:'DM Mono',monospace;font-size:12px;padding:2px 7px;border-radius:3px;}}
.sdc{{background:rgba(220,38,38,.1);color:#dc2626;border:1px solid rgba(220,38,38,.2);}}
.sdh{{background:rgba(234,88,12,.1);color:#ea580c;border:1px solid rgba(234,88,12,.2);}}
.sdm{{background:rgba(217,119,6,.1);color:#d97706;border:1px solid rgba(217,119,6,.2);}}
.sdl{{background:rgba(37,99,235,.1);color:#2563eb;border:1px solid rgba(37,99,235,.2);}}
.sdclean{{background:rgba(5,150,105,.08);color:#059669;border:1px solid rgba(5,150,105,.2);font-family:'DM Mono',monospace;font-size:12px;padding:2px 7px;border-radius:3px;}}
.rl{{font-size:13px;color:#4f46e5;text-decoration:none;font-family:'DM Mono',monospace;display:inline-flex;align-items:center;gap:4px;}}
.rl:hover{{text-decoration:underline;}}.nr{{font-size:13px;color:var(--mut);font-family:'DM Mono',monospace;}}
.pag{{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;border-top:1px solid var(--bdr);background:var(--sur2);transition:var(--t);}}
.pi{{font-size:13px;color:var(--mut);font-family:'DM Mono',monospace;}}.pbs{{display:flex;gap:6px;}}
.pb{{padding:5px 12px;border-radius:6px;border:1px solid var(--bdr);background:var(--sur);color:var(--dim);font-size:13px;font-family:'DM Mono',monospace;cursor:pointer;transition:all .15s;}}
.pb:hover:not(:disabled){{border-color:#4f46e5;color:#4f46e5;}}.pb:disabled{{opacity:.4;cursor:not-allowed;}}.pb.cur{{background:rgba(79,70,229,.08);border-color:#4f46e5;color:#4f46e5;}}
.footer{{text-align:center;padding:20px 40px;border-top:1px solid var(--bdr);color:var(--mut);font-size:12px;font-family:'DM Mono',monospace;}}
.footer a{{color:#4f46e5;text-decoration:none;}}.footer a:hover{{text-decoration:underline;}}
::-webkit-scrollbar{{width:5px;height:5px;}}::-webkit-scrollbar-track{{background:transparent;}}::-webkit-scrollbar-thumb{{background:var(--bdr);border-radius:3px;}}
</style>
</head>
<body>
<div class="header">
  <div class="hl"><div class="logo">🔍</div>
    <div><div class="an">GCP Security Agent — Summary</div></div>
  </div>
  <div class="hr2">
    <span class="hpill">📅 {scan_date}</span>
    <span class="hpill">🕐 {lookback}d window</span>
    <span class="tl" id="tl">🌙</span>
    <button class="tt" onclick="toggleTheme()" aria-label="Toggle theme"></button>
  </div>
</div>
<div class="container">
  <div class="obanner">
    <div class="otitle">Scan Scope</div>
    <div class="oid">{scope_label}</div>
    <div class="ometa" id="ometa"></div>
  </div>
  <div class="osc" id="osc"></div>
  <div class="fbar">
    <div class="sw"><span class="sico">🔎</span><input class="si" type="text" id="sb" placeholder="Search project ID..." oninput="af()"></div>
    <button class="fb active" id="btn-all"      onclick="sf('all')">All with findings</button>
    <button class="fb"        id="btn-critical" onclick="sf('critical')">Critical</button>
    <button class="fb"        id="btn-high"     onclick="sf('high')">High</button>
    <button class="fb"        id="btn-medium"   onclick="sf('medium')">Medium</button>
    <span class="rc" id="rc"></span>
  </div>
  <div class="ptw">
    <table class="pt">
      <thead><tr><th style="width:32px">#</th><th>Project ID</th><th>Worst Severity</th><th>Findings</th><th>Resources</th><th>Report</th></tr></thead>
      <tbody id="ptb"></tbody>
    </table>
    <div class="pag"><span class="pi" id="pi"></span><div class="pbs" id="pbs"></div></div>
  </div>
</div>
<div class="footer">
  GCP Security Agent &nbsp;·&nbsp; Reports generated for Medium+ projects only. Clean projects are logged but no report is created.
</div>
</div>
<script>
const ALL={rows_js};
const PS=10;let filtered=[...ALL],page=1,filt='all';
const sev={{critical:0,high:1,medium:2,low:3,minimal:4,clean:5}};
function sf(f){{filt=f;['all','critical','high','medium'].forEach(k=>document.getElementById('btn-'+k).classList.toggle('active',k===f));page=1;af();}}
function af(){{const q=document.getElementById('sb').value.toLowerCase();filtered=ALL.filter(p=>{{const ms=p.project_id.includes(q);const mf=filt==='all'?true:p.worst===filt;return ms&&mf;}});filtered.sort((a,b)=>(sev[a.worst]||9)-(sev[b.worst]||9));rt();}}
function rt(){{const tb=document.getElementById('ptb');const st=(page-1)*PS;const pg=filtered.slice(st,st+PS);document.getElementById('rc').textContent=filtered.length+' project'+(filtered.length!==1?'s':'');
tb.innerHTML='';
if(!pg.length){{tb.innerHTML=`<tr><td colspan="6" style="text-align:center;padding:32px;color:var(--mut);font-family:'DM Mono',monospace;font-size:13px;">No projects match.</td></tr>`;}}
else pg.forEach((p,i)=>{{const row=st+i+1;const dots=[];
if(p.critical>0)dots.push(`<span class="sd sdc">⛔ ${{p.critical}}</span>`);
if(p.high>0)dots.push(`<span class="sd sdh">🔴 ${{p.high}}</span>`);
if(p.medium>0)dots.push(`<span class="sd sdm">🟡 ${{p.medium}}</span>`);
if(p.low>0)dots.push(`<span class="sd sdl">🔵 ${{p.low}}</span>`);
if(!dots.length)dots.push('<span class="sdclean">✅ clean</span>');
const wb=p.worst==='critical'?'<span class="sb sb-critical">Critical</span>':p.worst==='high'?'<span class="sb sb-high">High</span>':p.worst==='medium'?'<span class="sb sb-medium">Medium</span>':p.worst==='low'?'<span class="sb sb-low">Low</span>':'<span class="sb sb-clean">Clean</span>';
const rl=p.report_file?`<a class="rl" href="${{p.report_file}}" target="_blank">📄 View report →</a>`:'<span class="nr">— low only</span>';
tb.innerHTML+=`<tr><td style="color:var(--mut);font-family:'DM Mono',monospace;font-size:12px">${{row}}</td><td class="pid2">${{p.project_id}}</td><td>${{wb}}</td><td><div class="sv">${{dots.join('')}}</div></td><td style="font-family:'DM Mono',monospace;font-size:13px">${{p.total_resources}}</td><td>${{rl}}</td></tr>`;
}});rp();}}
function rp(){{const tot=Math.ceil(filtered.length/PS);document.getElementById('pi').textContent=`Showing ${{Math.min((page-1)*PS+1,filtered.length)}}–${{Math.min(page*PS,filtered.length)}} of ${{filtered.length}}`;const pbs=document.getElementById('pbs');pbs.innerHTML='';const pv=document.createElement('button');pv.className='pb';pv.textContent='← Prev';pv.disabled=page===1;pv.onclick=()=>{{page--;rt();}};pbs.appendChild(pv);for(let i=1;i<=tot;i++){{const b=document.createElement('button');b.className='pb'+(i===page?' cur':'');b.textContent=i;b.onclick=((_i)=>()=>{{page=_i;rt();}})(i);pbs.appendChild(b);}}const nx=document.createElement('button');nx.className='pb';nx.textContent='Next →';nx.disabled=page===tot||tot===0;nx.onclick=()=>{{page++;rt();}};pbs.appendChild(nx);}}
function computeStats(){{const t=ALL.length,wf=ALL.filter(p=>p.worst!=='clean').length,cl=ALL.filter(p=>p.worst==='clean').length,wc=ALL.filter(p=>p.critical>0).length,wh=ALL.filter(p=>p.high>0).length,wm=ALL.filter(p=>p.medium>0&&p.critical===0&&p.high===0).length,wl=ALL.filter(p=>p.low>0&&p.medium===0&&p.critical===0&&p.high===0).length,tr2=ALL.reduce((s,p)=>s+p.total_resources,0);
document.getElementById('ometa').innerHTML=['🗂 '+t.toLocaleString()+' projects scanned','⚠️ '+wf.toLocaleString()+' with findings','✅ '+cl.toLocaleString()+' clean','📊 '+tr2.toLocaleString()+' total resources'].map(x=>`<span class="omchip">${{x}}</span>`).join('');
document.getElementById('osc').innerHTML=[['t-critical',wc,'⛔ Projects w/ Critical'],['t-high',wh,'🔴 Projects w/ High'],['t-medium',wm,'🟡 Medium only'],['t-low',wl,'🔵 Low only'],['t-minimal',0,'🟢 Minimal only'],['t-clean',cl,'✅ Clean']].map(([c,n,l])=>`<div class="osc-tile ${{c}}"><div class="osc-num">${{n}}</div><div class="osc-label">${{l}}</div></div>`).join('');}}
function toggleTheme(){{const h=document.documentElement,l=document.getElementById('tl');if(h.getAttribute('data-theme')==='dark'){{h.setAttribute('data-theme','light');l.textContent='☀️';}}else{{h.setAttribute('data-theme','dark');l.textContent='🌙';}}}}
computeStats();af();
</script>
</body></html>"""


# ──────────────────────────────────────────────────────────────────────────────
# PUBLIC API — called by main.py
# ──────────────────────────────────────────────────────────────────────────────

def generate_and_save_reports(
    classified_findings: list[dict],
    summary: dict,
    project_scope: str,
    scope_type: str,          # "project" | "folder" | "org"
    user_prompt: str,
    vertex_project: str,
    scan_date: str | None = None,
) -> dict:
    """
    Master entry point called by main.py.

    Behaviour by scope_type:
      project → per-project HTML only  (no summary)
      folder  → per-project HTML (Medium+) + folder summary HTML
      org     → per-project HTML (Medium+) + org summary HTML

    Returns:
      {
        "project_reports": ["output/report_....html", ...],
        "summary_report":  "output/summary_....html" | None,
      }
    """
    if not scan_date:
        scan_date = datetime.now().strftime("%Y-%m-%d")
    lookback = settings.TRAFFIC_LOOKBACK_DAYS
    if classified_findings:
        lookback = classified_findings[0].get("lookback_days", lookback)

    output_dir = _output_dir()
    ts = _ts()

    # ── group findings by project ──
    by_project: dict[str, list[dict]] = defaultdict(list)
    for f in classified_findings:
        by_project[f["project_id"]].append(f)

    # ── call Gemini ONCE for the full scope ──
    analysis = _call_gemini(
        findings=classified_findings,
        summary=summary,
        project_scope=project_scope,
        user_prompt=user_prompt,
        vertex_project=vertex_project,
    )

    # ── generate per-project reports (Medium+ only for folder/org) ──
    project_reports = []
    project_results = []   # for summary dashboard

    for pid, p_findings in by_project.items():
        from tools.risk_classifier import summarise_findings
        p_summary = summarise_findings(p_findings)

        worst = "clean"
        for lvl in ["critical", "high", "medium", "low"]:
            if p_summary.get(lvl.capitalize(), 0) > 0:
                worst = lvl
                break

        # build summary row for dashboard (always)
        project_results.append({
            "project_id":      pid,
            "worst":           worst,
            "critical":        p_summary.get("Critical", 0),
            "high":            p_summary.get("High", 0),
            "medium":          p_summary.get("Medium", 0),
            "low":             p_summary.get("Low", 0),
            "total_resources": p_summary.get("total", 0),
            "report_file":     None,  # filled in below if report generated
        })

        # per-project HTML only for Medium+ (or all if single project scan)
        needs_report = (
            scope_type == "project" or
            worst in ("critical", "high", "medium")
        )
        if not needs_report:
            continue

        html = _build_project_report_html(
            findings=p_findings,
            summary=p_summary,
            project_id=pid,
            project_scope=project_scope,
            analysis=analysis,
            scan_date=scan_date,
            lookback=lookback,
        )

        fname = f"report_{pid}_{ts}.html"
        fpath = output_dir / fname
        fpath.write_text(html, encoding="utf-8")
        logger.info(f"Project report saved: {fpath}")
        project_reports.append(str(fpath))

        # update report_file in summary row
        project_results[-1]["report_file"] = fname

    # ── generate summary HTML (folder/org only) ──
    summary_path = None
    if scope_type in ("folder", "org"):
        # sort by severity
        sev_ord = {"critical": 0, "high": 1, "medium": 2, "low": 3, "minimal": 4, "clean": 5}
        project_results.sort(key=lambda r: sev_ord.get(r["worst"], 5))

        summary_html = _build_org_summary_html(
            project_results=project_results,
            scope_label=project_scope,
            scan_date=scan_date,
            lookback=lookback,
        )
        safe = _safe_scope(project_scope)
        summary_fname = f"summary_{safe}_{ts}.html"
        summary_fpath = output_dir / summary_fname
        summary_fpath.write_text(summary_html, encoding="utf-8")
        logger.info(f"Summary report saved: {summary_fpath}")
        summary_path = str(summary_fpath)

    return {
        "project_reports": project_reports,
        "summary_report":  summary_path,
    }


# ── backwards-compat shims (used by old main.py before this session) ──────────
def generate_report(*args, **kwargs) -> str:
    """Deprecated — use generate_and_save_reports() instead."""
    logger.warning("generate_report() is deprecated — update main.py to use generate_and_save_reports()")
    return ""

def save_report(report: str, project_scope: str) -> str:
    """Deprecated — use generate_and_save_reports() instead."""
    logger.warning("save_report() is deprecated — update main.py to use generate_and_save_reports()")
    return ""
