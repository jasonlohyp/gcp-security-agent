# GCP Cloud Run Security Agent

A CLI tool that uses an AI agent (powered by Anthropic Claude) to analyse and
audit Google Cloud Run deployments and related BigQuery datasets using natural
language prompts.

---

## Description

The security agent accepts a natural language prompt and a GCP project ID, then
executes the relevant GCP API calls to investigate, report on, or remediate
security findings within Cloud Run and BigQuery. Credentials are sourced from
Application Default Credentials (ADC) — no API keys are ever hardcoded.

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/<your-org>/gcp-security-agent.git
cd gcp-security-agent
```

### 2. Create and activate a virtual environment

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` and fill in your values:

| Variable      | Description                                        |
|---------------|----------------------------------------------------|
| `PROJECT_ID`  | Default GCP project ID (can be overridden via CLI) |
| `BQ_DATASET`  | BigQuery dataset for security findings             |

### 5. Authenticate with GCP

```bash
gcloud auth application-default login
```

---

## Usage

```bash
python main.py --project <GCP_PROJECT_ID> --prompt "<natural language task>"
```

### Arguments

| Flag        | Required | Description                                              |
|-------------|----------|----------------------------------------------------------|
| `--project` | No*      | GCP Project ID. Overrides `PROJECT_ID` in `.env`.        |
| `--prompt`  | Yes      | Natural language description of the security task.       |

\* Required if `PROJECT_ID` is not set in `.env`.

---

## Example

```bash
python main.py \
  --project my-gcp-project-123 \
  --prompt "List all Cloud Run services with unauthenticated access enabled"
```

**Output:**

```
Agent initialized | Project: my-gcp-project-123 | Prompt: List all Cloud Run services with unauthenticated access enabled
```

---

## Project Structure

```
gcp-security-agent/
├── .env.example        # Template for environment variables
├── .gitignore          # Python + GCP credential exclusions
├── requirements.txt    # Python dependencies
├── README.md           # This file
├── main.py             # CLI entry point
├── config/
│   ├── __init__.py
│   └── settings.py     # Loads env vars via python-dotenv
└── tools/
    └── __init__.py     # Tools package (extend with GCP API wrappers)
```

---

## Security Notes

- **Never commit `.env`** — it is listed in `.gitignore`.
- **Never commit GCP service account JSON keys** — all `*.json` files (except
  `package.json`) are excluded by `.gitignore`.
- Use [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials)
  or Workload Identity for production deployments.