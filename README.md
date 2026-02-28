# gcp-security-agent

A GCP Cloud Run security agent that autonomously identifies public exposure risks and generates remediation steps. Built with Python, Vertex AI (Gemini 2.5 Flash), and GCP-native tooling. Designed to scale from a single project to an entire GCP organization.

---

## What It Does

1. **Resolves** target projects — single project, folder, or entire org
2. **Scans** all Cloud Run services in parallel for public exposure
3. **Estimates** cost and scope before running expensive operations (dry-run mode)
4. **Correlates** traffic logs via BigQuery to classify each service as `Safe` or `Risky`
5. **Generates** a markdown report with plain-language explanations and ready-to-apply `gcloud` fix commands — powered by Gemini 2.5 Flash on Vertex AI

---

## Architecture

```
CLI Input (--project | --folder | --org)
          │
          ▼
  project_resolver.py          ← resolves project list from GCP Resource Manager
          │
          ▼
  [--max-projects cap]         ← safety cap to limit scope
          │
          ▼
  ThreadPoolExecutor           ← parallel scan (max 10 workers)
  cloud_run_scanner.py         ← Cloud Run Admin API per project
          │
          ▼
  cost_estimator.py            ← scope + BQ cost estimate
  [--dry-run gate]             ← user confirms before BQ queries run
          │
          ▼
  traffic_analyzer.py          ← BigQuery log correlation (Safe/Risky)
          │
          ▼
  agent/orchestrator.py        ← Gemini 2.5 Flash report synthesis
          │
          ▼
  output/report_{timestamp}.md ← remediation report
```

---

## Tech Stack

| Component          | Technology                              |
|--------------------|-----------------------------------------|
| Language           | Python 3.11+                            |
| LLM                | Gemini 2.5 Flash (Vertex AI)            |
| Asset Discovery    | Google Cloud Run v2 Python SDK          |
| Project Resolution | Google Cloud Resource Manager v3 SDK    |
| Log Analysis       | Google Cloud BigQuery Python SDK        |
| Concurrency        | Python `concurrent.futures` (stdlib)    |
| Auth               | GCP Application Default Credentials     |
| IDE                | Google Antigravity                      |

---

## Project Structure

```
gcp-security-agent/
├── .env.example                  ← environment variable template
├── .gitignore
├── requirements.txt
├── README.md
├── main.py                       ← CLI entry point
├── config/
│   └── settings.py               ← env var loader
├── tools/
│   ├── __init__.py
│   ├── project_resolver.py       ← resolves project list (project/folder/org)
│   ├── cloud_run_scanner.py      ← discovers public Cloud Run services
│   ├── cost_estimator.py         ← dry-run scope + BQ cost estimation
│   └── traffic_analyzer.py       ← BQ traffic correlation (Safe/Risky)
├── agent/
│   └── orchestrator.py           ← Gemini report synthesis
└── output/                       ← generated reports (gitignored)
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

### 2. Create and activate virtual environment
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

### Single Project (personal / testing)
```bash
python main.py --project my-gcp-project --prompt "Analyze Cloud Run exposure"
```

### All Projects in a Folder (team / squad level)
```bash
python main.py --folder 123456789 --prompt "Analyze Cloud Run exposure"
```

### Entire Organization (company-wide scan)
```bash
python main.py --org 987654321 --prompt "Analyze Cloud Run exposure"
```

### Dry Run — Estimate Cost & Scope Before Executing
```bash
python main.py --org 987654321 --dry-run --prompt "Analyze Cloud Run exposure"
```

### Cap Number of Projects (safe testing at scale)
```bash
python main.py --org 987654321 --max-projects 50 --prompt "Analyze Cloud Run exposure"
```

### Combined Example
```bash
python main.py \
  --org 987654321 \
  --max-projects 100 \
  --dry-run \
  --prompt "Analyze Cloud Run exposure across all product teams"
```

Output report saved to `output/report_{timestamp}.md`.

---

## Dry Run Output Example

```
Resolved 134 projects to scan

╔══════════════════════════════════════╗
║         DRY RUN SUMMARY              ║
╠══════════════════════════════════════╣
║ Projects to scan       : 134         ║
║ Public services found  : 12          ║
║ BQ queries to run      : 12          ║
║ Estimated BQ scanned   : 6.0 GB      ║
║ Estimated BQ cost      : $0.03       ║
║ Estimated run time     : ~1.3 mins   ║
╚══════════════════════════════════════╝

Proceed with full scan? (y/n):
```

---

## Auth & Permissions

The agent uses **Application Default Credentials (ADC)** — no service account key files.

Minimum IAM roles required:

| Role | Purpose | Scope |
|------|---------|-------|
| `roles/run.viewer` | List Cloud Run services | Per project |
| `roles/bigquery.dataViewer` | Query log tables | Per project |
| `roles/bigquery.jobUser` | Run BQ jobs | Per project |
| `roles/logging.viewer` | Read Cloud Logging | Per project |
| `roles/aiplatform.user` | Call Vertex AI (Gemini) | Per project |
| `roles/resourcemanager.folderViewer` | List projects under a folder | Folder level |
| `roles/resourcemanager.organizationViewer` | List all projects in the org | Org level |

---

## Performance & Cost Design

| Mechanism | Detail |
|---|---|
| **Parallel scanning** | `ThreadPoolExecutor` with 10 workers — ~10x faster than sequential |
| **BQ cost guard** | `--dry-run` shows estimated GB scanned + USD cost before any queries run |
| **Project cap** | `--max-projects` limits scope during testing or staged rollouts |
| **Selective BQ queries** | Phase 3 only queries logs for public services found — not all projects |
| **Single LLM call** | Gemini is called once per run regardless of project count |

---

## Reusability

The agent is environment-agnostic. Switch between environments via `.env` or CLI flags:

```bash
# Personal project
python main.py --project jason-personal-project --prompt "Analyze Cloud Run exposure"

# Company org scan (no code changes needed)
python main.py --org HM_ORG_ID --prompt "Analyze Cloud Run exposure across all product teams"
```

---

## Dry Run Policy

**No changes are applied automatically.** The agent outputs `gcloud` commands for human review. Apply only after validating the report.

---

## Roadmap

- [x] Phase 1 — Scaffold + Auth
- [x] Phase 2 — Cloud Run Scanner + Performance Guards
- [ ] Phase 3 — Traffic Correlation (BigQuery)
- [ ] Phase 4 — Gemini Report + Remediation Output
- [ ] Phase 5 — IAM Basic Roles use case
