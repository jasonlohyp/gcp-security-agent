"""
Application settings loaded from environment variables via python-dotenv.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the project root (two levels up from this file)
_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_ENV_PATH)


class _Settings:
    """Centralised settings object.

    Values are read once at import time from the environment.
    The --project CLI flag in main.py takes precedence over PROJECT_ID.
    """

    PROJECT_ID: str = os.getenv("PROJECT_ID", "")
    BQ_DATASET: str = os.getenv("BQ_DATASET", "")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"Settings(PROJECT_ID={self.PROJECT_ID!r}, BQ_DATASET={self.BQ_DATASET!r})"
        )


settings = _Settings()
