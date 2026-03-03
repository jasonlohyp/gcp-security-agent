# file: config/settings.py

import os
from dotenv import load_dotenv

load_dotenv()

# ── Vertex AI / Gemini ────────────────────────────────────────────────────────
PROJECT_ID         = os.getenv("PROJECT_ID", "")
VERTEX_AI_LOCATION = os.getenv("VERTEX_AI_LOCATION", "europe-west1")
GEMINI_MODEL       = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

# ── Traffic Analysis (Cloud Logging API) ──────────────────────────────────────
TRAFFIC_LOOKBACK_DAYS  = int(os.getenv("TRAFFIC_LOOKBACK_DAYS", "30"))
# Max log entries fetched per project in the batch traffic query.
# 500 is sufficient for Active/Inactive classification across all services.
# Raise only if projects have >500 services and you need precise request counts.
LOG_BATCH_MAX_RESULTS  = int(os.getenv("LOG_BATCH_MAX_RESULTS", "500"))

# ── Report Output ─────────────────────────────────────────────────────────────
# Directory where HTML reports are written (relative or absolute path).
# On Cloud Run use /tmp/reports or a GCS-mounted path.
REPORT_OUTPUT_DIR      = os.getenv("REPORT_OUTPUT_DIR", "output")

# ── LLM Prompt Tuning ─────────────────────────────────────────────────────────
# Below this threshold: full per-finding detail sent to Gemini.
# At or above this threshold: category-level aggregates sent instead.
# Prevents token overflow on large folder/org scans.
# gemini-2.5-flash limit: 1M tokens. 200 findings ≈ 31k tokens (3% of limit).
REPORT_LLM_FINDINGS_THRESHOLD = int(os.getenv("REPORT_LLM_FINDINGS_THRESHOLD", "200"))

# ── Performance Guards ────────────────────────────────────────────────────────
MAX_WORKERS  = int(os.getenv("MAX_WORKERS", "10"))
MAX_PROJECTS = int(os.getenv("MAX_PROJECTS")) if os.getenv("MAX_PROJECTS") else None
