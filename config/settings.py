# file: config/settings.py

import os
from dotenv import load_dotenv

load_dotenv()

# GCP Project — overridable via CLI --project flag
PROJECT_ID = os.getenv("PROJECT_ID", "")

# BigQuery log configuration
BQ_DATASET = os.getenv("BQ_DATASET", "")
BQ_LOG_TABLE = os.getenv("BQ_LOG_TABLE", "cloudrun_googleapis_com_requests")

# Vertex AI / Gemini configuration
VERTEX_AI_LOCATION = os.getenv("VERTEX_AI_LOCATION", "europe-west1")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

# Traffic analysis window (days)
TRAFFIC_LOOKBACK_DAYS = int(os.getenv("TRAFFIC_LOOKBACK_DAYS", "30"))