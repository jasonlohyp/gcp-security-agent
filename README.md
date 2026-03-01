# gcp-security-agent

A GCP Cloud Run security agent that autonomously identifies public exposure risks, classifies them against a structured risk matrix, and generates remediation steps. Built with Python, Vertex AI (Gemini 2.5 Flash), and GCP-native tooling. Scales from a single project to an entire GCP organization.

---

## What It Does

1. **Resolves** target projects — single project, folder, or entire org
2. **Scans** all Cloud Run services in parallel for public exposure
3. **Estimates** cost and scope before running (dry-run mode)
4. **Correlates** traffic logs via Cloud Logging API to enrich findings
5. **Classifies** each service against a 6-tier risk matrix — pure Python, zero LLM cost
6. **Generates** ready-to-copy `gcloud` remediation commands per risk category — zero LLM cost
7. **Synthesizes** a single Gemini 2.5 Flash call to produce a narrative markdown report

---

## Architecture

```
CLI Input (--project | --folder | --org)
          │
          ▼
  project_resolver.py          ← GCP Resource Manager API
          │
          ▼
  [--max-projects cap]
          │
          ▼
  ThreadPoolExecutor            ← parallel scan (10 workers)
  cloud_run_scanner.py          ← Cloud Run Admin API
          │
          ▼
  cost_estimator.py + [--dry-run gate]
          │
          ▼
  traffic_analyzer.py           ← Cloud Logging API
          │
          ▼
  risk_classifier.py            ← deterministic Python — zero LLM cost
          │      ▲
          │      └── reads logic from config/risk_matrix.md
          ▼
  remediation_templates.py      ← Jinja2 gcloud commands — zero LLM cost
          │
          ▼
  orchestrator.py               ← ONE Gemini 2.5 Flash call
          │      ▲
          │      └── reads config/risk_matrix.md as system prompt context
          ▼
  output/report_{scope}_{ts}.md
```

---

## How the LLM is Used

The LLM (Gemini 2.5 Flash) plays a **narrow, well-defined role** — it is a report synthesizer, not a decision maker. All security decisions happen in Python before the LLM is ever called.

### What Gemini does NOT do
- ❌ Classify risk — handled by `risk_classifier.py` (pure Python)
- ❌ Determine ingress/auth/SA issues — handled by `cloud_run_scanner.py`
- ❌ Generate `gcloud` commands — handled by `remediation_templates.py` (Jinja2)
- ❌ Query logs or APIs — handled by `traffic_analyzer.py`

### What Gemini DOES do (one call per run)
- ✅ Writes the executive summary in plain language
- ✅ Explains in plain English *why* each service is risky based on pre-computed triggered dimensions
- ✅ Presents pre-computed remediation commands in the report exactly as provided
- ✅ Adds strategic recommendations based on patterns across all findings

### Why this design?
Keeping classification deterministic (Python) and synthesis separate (LLM) means:
- **Consistent results** — same inputs always produce the same risk category
- **Auditable logic** — risk rules live in `config/risk_matrix.md`, readable by anyone
- **Cost efficient** — one LLM call at ~$0.01 regardless of how many projects or services are scanned
- **No hallucination risk on facts** — Gemini only narrates, never decides

---

## Key File Responsibilities

| File | Role | Uses LLM? |
|---|---|---|
| `config/risk_matrix.md` | Single source of truth for risk classification logic. Read by `risk_classifier.py` (as code reference) and injected into Gemini system prompt by `orchestrator.py`. Update this file to evolve security standards — no code changes needed. | No |
| `tools/risk_classifier.py` | Pure Python 6-tier risk classifier. Reads ingress, auth, SA, and traffic data and assigns a risk category. Called for every finding before the LLM is invoked. | No |
| `tools/remediation_templates.py` | Jinja2 templates that generate ready-to-copy `gcloud` fix commands per risk category. Output stored in `finding["remediation"]` and passed to Gemini as pre-computed context — Gemini presents them, never rewrites them. | No |
| `agent/orchestrator.py` | The only file that calls Gemini. Receives fully classified and remediated findings, loads `risk_matrix.md` as system context, and asks Gemini to write a narrative report. One API call per run. | ✅ Yes — once |
| `tools/cloud_run_scanner.py` | Calls Cloud Run Admin API to list all services and extract ingress, auth, and service account config. | No |
| `tools/traffic_analyzer.py` | Queries Cloud Logging API for request counts within the configured lookback window. Classifies traffic as Active or Inactive. | No |
| `tools/project_resolver.py` | Resolves a single project, folder, or org into a flat list of active project IDs using Resource Manager API. | No |
| `tools/cost_estimator.py` | Calculates scope summary for the dry-run gate — project count, public services found, and estimated run time. | No |
| `config/settings.py` | Loads all environment variables from `.env`. Single place to read config — all other files import from here. | No |
| `main.py` | CLI entry point. Orchestrates the full pipeline in order: resolve → scan → traffic → classify → remediate → report. | No |

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.11+ |
| LLM | Gemini 2.5 Flash (Vertex AI) — single call per run |
| Risk Classification | Pure Python against `config/risk_matrix.md` |
| Remediation Commands | Jinja2 templates per risk category |
| Asset Discovery | Google Cloud Run v2 Python SDK |
| Traffic Analysis | Google Cloud Logging Python SDK |
| Project Resolution | Google Cloud Resource Manager v3 SDK |
| Concurrency | Python `concurrent.futures` (stdlib) |
| Auth | GCP Application Default Credentials (ADC) |
| IDE | Google Antigravity |

---

## Risk Matrix (6-Tier)

| Category | Conditions | Risk Level |
|---|---|---|
| Critical: Exposed & Abandoned | ingress=all + unauthenticated + no traffic | Critical |
| High: Public Direct Access | ingress=all + unauthenticated + has traffic | High |
| Medium: Identity Leakage | ingress=all + authenticated + default SA | Medium |
| Medium: LB Bypass Risk | ingress=all + authenticated | Medium |
| Low: Shielded | ingress=internal-and-LB + authenticated | Low |
| Minimal: Zero Trust | ingress=internal + custom SA + VPC SC | Minimal |

Full logic and LLM instructions defined in `config/risk_matrix.md`.
**To update risk standards — edit `risk_matrix.md` only. No code changes needed.**

---

## Project Structure

```
gcp-security-agent/
├── .env.example
├── .gitignore
├── requirements.txt
├── README.md
├── main.py                        ← CLI entry point + pipeline orchestration
├── config/
│   ├── settings.py                ← env var loader (single source of config)
│   └── risk_matrix.md             ← risk classification logic (single source of truth)
├── tools/
│   ├── __init__.py
│   ├── project_resolver.py        ← resolves project list from project/folder/org
│   ├── cloud_run_scanner.py       ← discovers public Cloud Run services
│   ├── traffic_analyzer.py        ← Cloud Logging traffic correlation (Active/Inactive)
│   ├── risk_classifier.py         ← deterministic 6-tier Python risk classification
│   ├── cost_estimator.py          ← dry-run scope + run time estimation
│   └── remediation_templates.py   ← Jinja2 gcloud fix commands per risk category
├── agent/
│   └── orchestrator.py            ← single Gemini 2.5 Flash report synthesis call
└── output/                        ← generated reports (gitignored)
```

---

## Setup

### Prerequisites
- Python 3.11+
- GCP project with Cloud Run and Vertex AI enabled
- `gcloud` CLI installed and authenticated

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/gcp-security-agent.git
cd gcp-security-agent
```

### 2. Create and activate virtual environment
```bash
python -m venv .venv
.venv\Scripts\activate      # Windows
source .venv/bin/activate   # macOS/Linux
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Set up environment variables
```bash
cp .env.example .env
# Edit .env with your values
```

### 5. Authenticate with GCP
```bash
gcloud auth application-default login
```

### 6. Enable required GCP APIs
```bash
gcloud services enable \
  run.googleapis.com \
  logging.googleapis.com \
  cloudresourcemanager.googleapis.com \
  aiplatform.googleapis.com \
  --project YOUR_PROJECT_ID
```

---

## Usage

```bash
# Single project
python main.py --project my-project --prompt "Analyze Cloud Run exposure"

# All projects in a folder
python main.py --folder 123456789 --prompt "Analyze Cloud Run exposure"

# Entire org
python main.py --org 987654321 --prompt "Analyze Cloud Run exposure"

# Dry run — estimate scope first (recommended before large scans)
python main.py --org 987654321 --dry-run --prompt "Analyze Cloud Run exposure"

# Cap projects for safe testing
python main.py --org 987654321 --max-projects 50 --prompt "Analyze Cloud Run exposure"
```

---

## Performance & Cost at Scale

### Cost Projection

| Component | Operations | Cost |
|---|---|---|
| Resource Manager API | 1 call to resolve projects | Free |
| Cloud Run Admin API | 1 call per project | Free |
| Cloud Logging API | 1 query per public service found | Free |
| Risk classification | Pure Python per service | Free |
| Remediation templates | Jinja2 render per service | Free |
| **Gemini 2.5 Flash** | **1 call per run — flat** | **~$0.01–$0.05** |

**Total cost: under $0.05 per full org scan regardless of project count.**

The Gemini cost is proportional to the number of public services found (token count), not the number of projects scanned. Scanning 1500 projects with 5 public services costs the same as scanning 10 projects with 5 public services.

---

### Performance Projection

| Projects | Workers | Estimated Scan Time |
|---|---|---|
| 10 | 10 | ~5 seconds |
| 100 | 10 | ~30 seconds |
| 500 | 10 | ~2.5 minutes |
| 1500 | 10 | ~7–8 minutes |
| 1500 | 20 | ~4 minutes |

The bottleneck is the Cloud Run scanning phase. Traffic analysis, classification, and report generation add less than 30 seconds regardless of scale.

---

### API Quota Considerations

The Cloud Run Admin API has a default quota of **600 requests/minute**. At `MAX_WORKERS=10` scanning ~1500 projects, you may approach this limit.

**Recommended approach for large orgs:**

**Option 1 — Scan by folder (safest)**
```bash
# Scan one team/folder at a time — stays well under quota
python main.py --folder TEAM_A_FOLDER_ID --prompt "Analyze Cloud Run exposure"
python main.py --folder TEAM_B_FOLDER_ID --prompt "Analyze Cloud Run exposure"
```
This also produces per-team reports which are easier for team leads to action.

**Option 2 — Reduce workers**
```bash
# In .env — reduce to 5 workers to stay under quota
MAX_WORKERS=5
```

**Option 3 — Increase workers for trusted large orgs**
```bash
# In .env — increase to 20 workers if quota allows
# First check your quota: GCP Console → IAM → Quotas → Cloud Run API
MAX_WORKERS=20
```

**To check and increase your Cloud Run API quota:**
```
GCP Console → APIs & Services → Cloud Run Admin API → Quotas
```

---

### Known Behaviours at Scale

| Scenario | Behaviour |
|---|---|
| Project has Cloud Run API disabled | Scanner logs a warning and skips — does not fail the run |
| Project has no Cloud Run services | Returns empty findings — counted in progress, excluded from report |
| Logging API unavailable for a service | Traffic classified as `Unknown` — still included in report with a warning |
| Gemini token limit exceeded (50+ findings) | Split scan by folder to reduce findings per report |

---

## Performance & Cost Design Summary

| Component | LLM Calls | Cost |
|---|---|---|
| Project resolution | 0 | Free |
| Cloud Run scanning (parallel) | 0 | Free |
| Traffic analysis (Cloud Logging) | 0 | Free |
| Risk classification | 0 | Free — pure Python |
| Remediation generation | 0 | Free — Jinja2 templates |
| Report synthesis | **1 per run** | ~$0.01–$0.05 flat |

---

## Auth & Permissions

Uses **Application Default Credentials (ADC)** — no service account key files.

| Role | Purpose | Scope |
|---|---|---|
| `roles/run.viewer` | List Cloud Run services | Per project |
| `roles/logging.viewer` | Read Cloud Logging | Per project |
| `roles/aiplatform.user` | Call Vertex AI (Gemini) | Per project |
| `roles/resourcemanager.folderViewer` | List projects under folder | Folder level |
| `roles/resourcemanager.organizationViewer` | List all org projects | Org level |

---

## Reusability

The agent is environment-agnostic. Switch targets using CLI flags — no code changes needed:

```bash
# Single project
python main.py --project my-dev-project --prompt "Analyze Cloud Run exposure"

# Team folder
python main.py --folder FOLDER_ID --prompt "Analyze Cloud Run exposure"

# Full org scan
python main.py --org ORG_ID --prompt "Analyze Cloud Run exposure"
```

---

## Dry Run Policy

**No changes are applied automatically.** All remediation output is `gcloud` commands for human review only. Always use `--dry-run` first when scanning a large scope to verify project count and estimated run time before proceeding.

---

## Roadmap

- [x] Phase 1 — Scaffold + Auth
- [x] Phase 2 — Cloud Run Scanner + Performance Guards
- [x] Phase 3 — Traffic Correlation (Cloud Logging API)
- [x] Phase 4 — Gemini 2.5 Flash Report + 6-Tier Risk Matrix + Remediation Templates
- [ ] Phase 5 — Per-folder report generation (one report per team/folder)
- [ ] Phase 6 — Schedule as Cloud Run Job (automated weekly scans)
- [ ] Phase 7 — Email/Slack notification for Critical and High findings
- [ ] Phase 8 — Multi-region parallel scanning optimisation

---

## License

MIT
