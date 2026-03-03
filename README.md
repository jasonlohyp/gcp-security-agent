# gcp-security-agent

Autonomously identifies public exposure risks across **Cloud Run Services** and **Cloud Functions (Gen1 + Gen2)**, classifies them against a structured risk matrix, and generates HTML security reports with ready-to-run remediation scripts. Scales from a single project to an entire GCP organization.

---

## What It Does

1. **Resolves** target projects — single project, folder, or entire org
2. **Scans** Cloud Run Services + Cloud Functions Gen1 and Gen2 in parallel
3. **Flags** Gen1 functions for migration to Gen2
4. **Correlates** traffic logs (1 Cloud Logging batch query per project — quota safe)
5. **Classifies** each resource against an 11-tier risk matrix — pure Python, zero LLM cost
6. **Generates** ready-to-run `gcloud` remediation scripts per risk group — zero LLM cost
7. **Synthesizes** a single LLM call to produce narrative analysis and smart pattern detection
8. **Renders** self-contained HTML reports — dark/light theme toggle, copy-paste bash scripts

---

## Report Output Strategy

| CLI flag | Output |
|---|---|
| `--project` | One per-project HTML report |
| `--folder` | Per-project HTML (Medium+ only) + folder summary dashboard |
| `--org` | Per-project HTML (Medium+ only) + org summary dashboard |

Low-only and clean projects are logged in the summary dashboard but no individual report is created.

---

## Architecture

```
CLI (--project | --folder | --org | --resource)
        |
        v
project_resolver.py          <- GCP Resource Manager API
        |
        v
ThreadPoolExecutor            <- parallel scan across projects
+---------------------------+
| cloud_run_scanner.py      |  <- Cloud Run Admin API
| cloud_functions_scanner   |  <- Cloud Functions API v1 + v2
+---------------------------+
        |
        v
traffic_analyzer.py           <- Cloud Logging API (1 batch query per project)
        |
        v
risk_classifier.py            <- deterministic Python -- zero LLM cost
        |
        v
remediation_templates.py      <- gcloud commands -- zero LLM cost
        |
        v
orchestrator.py               <- ONE LLM call (narrative + pattern analysis)
        |
        v
output/
  report_<pid>_<ts>.html      <- per-project (Medium+ only for folder/org)
  summary_<scope>_<ts>.html   <- folder/org scans only
```

---

## Setup

### Prerequisites
- Python 3.11+
- GCP project with Vertex AI enabled
- `gcloud` CLI authenticated

```bash
git clone https://github.com/YOUR_USERNAME/gcp-security-agent.git
cd gcp-security-agent
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env   # edit with your values
gcloud auth application-default login
```

### Required GCP APIs
```bash
gcloud services enable \
  run.googleapis.com \
  cloudfunctions.googleapis.com \
  logging.googleapis.com \
  cloudresourcemanager.googleapis.com \
  aiplatform.googleapis.com \
  --project YOUR_VERTEX_PROJECT
```

### Key `.env` variables
```dotenv
PROJECT_ID=your-vertex-ai-project   # used for LLM auth only -- NOT the scan target
GEMINI_MODEL=gemini-2.5-flash-preview-04-17
VERTEX_AI_LOCATION=us-central1
TRAFFIC_LOOKBACK_DAYS=30
MAX_WORKERS=10
MAX_PROJECTS=1500
```

---

## Usage

```bash
# Scan a single project
python main.py --project my-project

# Scan a folder -- per-project reports + folder summary dashboard
python main.py --folder 123456789

# Scan entire org -- per-project reports + org summary dashboard
python main.py --org 987654321

# Dry run -- estimate scope before committing
python main.py --org 987654321 --dry-run

# Cap projects (useful for testing)
python main.py --org 987654321 --max-projects 20

# Use a separate project for LLM auth
python main.py --project company-project --vertex-project my-personal-project

# Filter by resource type
python main.py --project my-project --resource cloud-run
python main.py --project my-project --resource cloud-functions
```

---

## Project ID Separation

| Setting | Purpose | Where |
|---|---|---|
| `--project` / `--folder` / `--org` | Scan target | CLI flag |
| `PROJECT_ID` in `.env` | LLM auth — which project pays for the API call | `.env` |
| `--vertex-project` | LLM auth override for a single run | CLI flag |

---

## Required IAM Roles

| Role | Where |
|---|---|
| `roles/run.viewer` | Scan target project(s) |
| `roles/cloudfunctions.viewer` | Scan target project(s) |
| `roles/logging.viewer` | Scan target project(s) |
| `roles/resourcemanager.folderViewer` | Folder (if using `--folder`) |
| `roles/resourcemanager.organizationViewer` | Org root (if using `--org`) |
| `roles/aiplatform.user` | Vertex AI project only |

---

## Risk Matrix (11-Tier)

| Category | Ingress | Auth | Traffic | Level |
|---|---|---|---|---|
| Critical: Exposed & Abandoned | all | No | 0 | Critical |
| High: Public Direct Access | all | No | >0 | High |
| High: LB Exposed & Abandoned | LB | No | 0 | High |
| Medium: LB Unauthenticated | LB | No | >0 | Medium |
| Medium: Identity Leakage | all | Yes | any | Medium |
| Medium: LB Bypass Risk | all | Yes | any | Medium |
| Low: Shielded | LB | Yes | any | Low |
| Low: Internal Unauthenticated | internal | No | any | Low |
| Minimal: Zero Trust | internal | Yes | any | Minimal |

Full logic in `config/risk_matrix.md` — edit to evolve security standards, no code changes needed.

---

## How the LLM Is Used

One call per run for narrative analysis only. All security decisions are made in Python before the LLM is invoked.

| Task | Where |
|---|---|
| Risk classification | `risk_classifier.py` — pure Python |
| Remediation commands | `remediation_templates.py` — Jinja2 |
| Traffic correlation | `traffic_analyzer.py` — Cloud Logging API |
| Executive summary + pattern analysis | `orchestrator.py` — single LLM call |

**Cost: ~$0.01 per full org scan** regardless of project or finding count.

---

## Key Files

| File | Role |
|---|---|
| `main.py` | CLI entry point + pipeline orchestration |
| `config/settings.py` | Env var loading — single config source |
| `config/risk_matrix.md` | Risk classification logic — single source of truth |
| `agent/orchestrator.py` | LLM call + HTML report generation |
| `tools/risk_classifier.py` | 11-tier deterministic risk classification |
| `tools/remediation_templates.py` | Jinja2 `gcloud` fix commands |
| `tools/cloud_run_scanner.py` | Cloud Run Services discovery |
| `tools/cloud_functions_scanner.py` | Cloud Functions Gen1 + Gen2 discovery |
| `tools/traffic_analyzer.py` | Cloud Logging batch traffic correlation |
| `tools/project_resolver.py` | Project list resolution from project/folder/org |
| `tools/cost_estimator.py` | Dry-run scope estimation |

---

## Roadmap

- [x] Cloud Run Scanner + Performance Guards
- [x] Traffic Correlation (Cloud Logging API)
- [x] LLM Report + Risk Matrix + Remediation Templates
- [x] Cloud Functions Gen1 + Gen2 Scanner + Gen1 Migration Warning
- [x] HTML Reports (per-project + org/folder summary dashboard)
- [ ] Natural language prompt parsing (filter by risk level, drill down on specific service)
- [ ] GCS Scanner (public bucket exposure — IAM, ACLs, CORS)

---

## License

MIT
