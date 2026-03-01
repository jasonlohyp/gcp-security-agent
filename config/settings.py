# file: config/settings.py

import os
from dotenv import load_dotenv

load_dotenv()

# GCP Project
PROJECT_ID = os.getenv("PROJECT_ID", "")

# Vertex AI / Gemini
VERTEX_AI_LOCATION = os.getenv("VERTEX_AI_LOCATION", "europe-west1")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

# Traffic Analysis (Cloud Logging API)
TRAFFIC_LOOKBACK_DAYS = int(os.getenv("TRAFFIC_LOOKBACK_DAYS", "30"))

# Performance Guards
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "10"))
MAX_PROJECTS = int(os.getenv("MAX_PROJECTS")) if os.getenv("MAX_PROJECTS") else None
