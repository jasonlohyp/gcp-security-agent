# gcp-security-agent

A GCP Cloud Run security agent that autonomously identifies public exposure risks and generates remediation steps. Built with Python, Vertex AI (Gemini 2.5 Flash), and GCP-native tooling.

---

## What It Does

1. **Scans** all Cloud Run services in a GCP project for public exposure
2. **Correlates** traffic logs via BigQuery to classify each service as `Safe` or `Risky`
3. **Generates** a markdown report with plain-language explanations and ready-to-apply `gcloud` fix commands — powered by Gemini 2.5 Flash on Vertex AI

---

## Architecture

```
User Prompt (CLI)
      │
      ▼
  main.py  ──────────────────────────────────────────┐
      │                                               │
      ▼                                               ▼
cloud_run_scanner.py          traffic_analyzer.py     agent/orchestrator.py
(Cloud Run API)               (BigQuery log query)    (Gemini 2.5 Flash)
      │                               │                       │
      └───────────── findings ────────┘                       │
                         │                                     │
                         └──────────── report.md ─────────────┘
```

---

## Tech Stack

| Component         | Technology                        |
|-------------------|-----------------------------------|
| Language          | Python 3.11+                      |
| LLM               | Gemini 2.5 Flash (Vertex AI)      |
| Asset Discovery   | Google Cloud Run v2 Python SDK    |
| Log Analysis      | Google Cloud BigQuery Python SDK  |
| Auth              | GCP Application Default Credentials (ADC) |
| IDE               | Google Antigravity                |

---

## Project Structure

```
gcp-security-agent/
├── .env.example              ← environment variable template
├── .gitignore
├── requirements.txt
├── README.md
├── main.py                   ← CLI entry point
├── config/
│   └── settings.py           ← env var loader
├── tools/
│   ├── __init__.py
│   ├── cloud_run_scanner.py  ← discovers public Cloud Run services
│   └── traffic_analyzer.py  ← BQ traffic correlation (Safe/Risky)
├── agent/
│   └── orchestrator.py       ← Gemini report synthesis
└── output/                   ← generated reports (gitignored)
```

---

## Setup

### Prerequisites
- Python 3.11+
- GCP project with Cloud Run and BigQuery enabled
- `gcloud` CLI installed and authenticated

### 1. Clone the repo
```bash
git clone https://github.com/jasonlohyp/gcp-security-agent.git
cd gcp-security-agent
```

### 2. Create and activate a virtual environment
```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Set up environment variables
```bash
cp .env.example .env
# Edit .env with your project values
```

### 5. Authenticate with GCP
```bash
gcloud auth application-default login
```

---

## Usage

```bash
# Basic scan — project from .env
python main.py --prompt "Analyze Cloud Run public exposure"

# Override project via CLI
python main.py --project my-gcp-project --prompt "Analyze Cloud Run public exposure"

# Scope to specific region
python main.py --project my-gcp-project --prompt "Analyze Cloud Run exposure in europe-west1"
```

Output report is saved to `output/report_{timestamp}.md`.

---

## Auth & Permissions

The agent uses **Application Default Credentials (ADC)** — no service account key files.

Minimum IAM roles required on the target project:

| Role | Purpose |
|------|---------|
| `roles/run.viewer` | List Cloud Run services |
| `roles/bigquery.dataViewer` | Query log tables |
| `roles/bigquery.jobUser` | Run BQ jobs |
| `roles/logging.viewer` | Read Cloud Logging |
| `roles/aiplatform.user` | Call Vertex AI (Gemini) |

---

## Reusability

The agent is environment-agnostic. Switch between projects by swapping `.env` or using the `--project` CLI flag:

```bash
# Personal project
python main.py --project jason-personal-project --prompt "Analyze Cloud Run exposure"

# Company project (no code changes)
python main.py --project hm-aiad-prod --prompt "Analyze Cloud Run exposure"
```

---

## Dry Run Policy

**No changes are applied automatically.** The agent outputs `gcloud` commands and Terraform snippets for human review. Apply only after validating the report.

---

## Roadmap

- [x] Phase 1 — Scaffold + Auth
- [ ] Phase 2 — Cloud Run Scanner
- [ ] Phase 3 — Traffic Correlation (BigQuery)
- [ ] Phase 4 — Gemini Report + Remediation Output
- [ ] Phase 5 — IAM Basic Roles use case
