"""
GCP Cloud Run Security Agent CLI
Entry point for the security agent tool.
"""

import argparse
from config.settings import settings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GCP Cloud Run Security Agent CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --project my-gcp-project --prompt "List all Cloud Run services"
  python main.py --project my-gcp-project --prompt "Check IAM bindings for service foo"
        """,
    )
    parser.add_argument(
        "--project",
        type=str,
        required=False,
        help="GCP Project ID (overrides PROJECT_ID from .env)",
    )
    parser.add_argument(
        "--prompt",
        type=str,
        required=True,
        help="Natural language prompt describing the security task",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # CLI --project flag overrides the value loaded from .env
    project_id = args.project or settings.PROJECT_ID

    if not project_id:
        raise ValueError(
            "A GCP Project ID is required. Provide --project or set PROJECT_ID in .env"
        )

    print(f"Agent initialized | Project: {project_id} | Prompt: {args.prompt}")


if __name__ == "__main__":
    main()
