import os
from dotenv import load_dotenv

load_dotenv()

# GCP Project — overridable via CLI --project flag
PROJECT_ID = os.getenv("PROJECT_ID", "")
FOLDER_ID = os.getenv("FOLDER_ID", "")
ORG_ID = os.getenv("ORG_ID", "")

# BigQuery log configuration
BQ_DATASET = os.getenv("BQ_DATASET", "")
BQ_LOG_TABLE = os.getenv("BQ_LOG_TABLE", "cloudrun_googleapis_com_requests")

# Vertex AI / Gemini configuration
VERTEX_AI_LOCATION = os.getenv("VERTEX_AI_LOCATION", "europe-west1")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

# Traffic analysis window (days)
TRAFFIC_LOOKBACK_DAYS = int(os.getenv("TRAFFIC_LOOKBACK_DAYS", "30"))

# Production Guards
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "10"))
MAX_PROJECTS = int(os.getenv("MAX_PROJECTS")) if os.getenv("MAX_PROJECTS") else None
BQ_COST_PER_GB = float(os.getenv("BQ_COST_PER_GB", "0.005"))
DEFAULT_BQ_GB_PER_QUERY = float(os.getenv("DEFAULT_BQ_GB_PER_QUERY", "0.5"))