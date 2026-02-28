# file: main.py

import argparse
from config import settings

def parse_args():
    parser = argparse.ArgumentParser(
        description="GCP Security Agent — Cloud Run Public Exposure Scanner"
    )
    parser.add_argument(
        "--project",
        type=str,
        help="GCP Project ID (overrides PROJECT_ID in .env)",
        default=None
    )
    parser.add_argument(
        "--prompt",
        type=str,
        help='Natural language prompt e.g. "Analyze Cloud Run public exposure"',
        required=True
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # CLI --project overrides .env PROJECT_ID
    project_id = args.project or settings.PROJECT_ID

    if not project_id:
        raise ValueError("Project ID is required. Pass --project or set PROJECT_ID in .env")

    print(f"Agent initialized | Project: {project_id} | Prompt: {args.prompt}")
    print(f"LLM: {settings.GEMINI_MODEL} @ {settings.VERTEX_AI_LOCATION}")
    print(f"Traffic lookback: {settings.TRAFFIC_LOOKBACK_DAYS} days")
    print("---")
    print("Phase 2 (Cloud Run Scanner) coming next...")


if __name__ == "__main__":
    main()

