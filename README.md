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
  traffic_analyzer.py           ← Cloud Logging API (parallel)
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
          │      └── uses --vertex-project or PROJECT_ID in .env for auth
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
| `agent/orchestrator.py` | The only file that calls Gemini. Receives fully classified and remediated findings, loads `risk_matrix.md` as system context, and asks Gemini to write a narrative report. One API call per run. Authenticated using `--vertex-project` or `PROJECT_ID` in `.env`. | ✅ Yes — once |
| `tools/cloud_run_scanner.py` | Calls Cloud Run Admin API to list all services and extract ingress, auth, and service account config. Accepts `project_number` from `project_resolver.py` — no extra API call needed. | No |
| `tools/traffic_analyzer.py` | Queries Cloud Logging API for request counts within the configured lookback window. Runs in parallel. Classifies traffic as Active or Inactive. | No |
| `tools/project_resolver.py` | Resolves a single project, folder, or org into a flat list of active projects. Returns both `project_id` and `project_number` in a single API call — eliminates redundant `get_project` calls downstream. | No |
| `tools/cost_estimator.py` | Calculates scope summary for the dry-run gate — project count, public services found, and estimated run time. | No |
| `config/settings.py` | Loads all environment variables from `.env`. Single place to read config — all other files import from here. | No |
| `main.py` | CLI entry point. Orchestrates the full pipeline in order: resolve → scan → traffic → classify → remediate → report. Separates scan scope (`--project/--folder/--org`) from Vertex AI auth (`--vertex-project` or `PROJECT_ID` in `.env`). | No |

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
| High: LB Exposed & Abandoned | ingress=LB + unauthenticated + no traffic | High |
| Medium: LB Unauthenticated | ingress=LB + unauthenticated + has traffic | Medium |
| Medium: Identity Leakage | ingress=all + authenticated + default SA | Medium |
| Medium: Identity Leakage (LB) | ingress=LB + authenticated + default SA | Medium |
| Medium: LB Bypass Risk | ingress=all + authenticated | Medium |
| Low: Shielded | ingress=LB + authenticated + custom SA | Low |
| Minimal: Zero Trust | ingress=internal | Minimal |

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
│   ├── project_resolver.py        ← resolves project list + project numbers
│   ├── cloud_run_scanner.py       ← discovers public Cloud Run services
│   ├── traffic_analyzer.py        ← Cloud Logging traffic correlation (parallel)
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

**Key `.env` variable:**
```dotenv
# PROJECT_ID is used exclusively for Vertex AI / Gemini authentication.
# It is NOT the scan target — use --project / --folder / --org for that.
# Your account must have roles/aiplatform.user on this project.
PROJECT_ID=your-vertex-ai-project
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
python main.py --project my-project

# All projects in a folder
python main.py --folder 123456789

# Entire org
python main.py --org 987654321

# With custom prompt
python main.py --project my-project --prompt "Analyze Cloud Run exposure"

# Dry run — estimate scope first (recommended before large scans)
python main.py --org 987654321 --dry-run

# Cap projects for safe testing
python main.py --org 987654321 --max-projects 10

# Scan a company project using a different project for Gemini auth
python main.py --project company-project --vertex-project my-personal-project
```

---

## Project ID Separation — Scan Target vs Vertex AI Auth

This is the most important configuration concept in the agent.

Two project IDs serve different purposes and are intentionally independent:

| Setting | Purpose | Where to set |
|---|---|---|
| `--project` / `--folder` / `--org` | **Scan target** — what gets scanned for Cloud Run exposure | CLI flag |
| `PROJECT_ID` in `.env` | **Vertex AI auth** — which project pays for and authenticates Gemini | `.env` file |
| `--vertex-project` | **Vertex AI auth override** — overrides `PROJECT_ID` in `.env` for a single run | CLI flag |

### Why they are separate

You often want to **scan a project you don't own** (e.g. a company project) while **authenticating Gemini via a project you do own** (e.g. your personal project with `roles/aiplatform.user`).

```bash
# Scan company project, authenticate Gemini via personal project
python main.py \
  --project company-project-id \
  --vertex-project my-personal-project

# Or set PROJECT_ID=my-personal-project in .env and just pass --project
python main.py --project company-project-id
```

### Required IAM roles

| Role | Project | Purpose |
|---|---|---|
| `roles/run.viewer` | Scan target project(s) | List Cloud Run services |
| `roles/logging.viewer` | Scan target project(s) | Read Cloud Logging |
| `roles/resourcemanager.folderViewer` | Folder (if using --folder) | List projects under folder |
| `roles/resourcemanager.organizationViewer` | Org (if using --org) | List all org projects |
| `roles/aiplatform.user` | **Vertex AI project only** (`PROJECT_ID` or `--vertex-project`) | Call Gemini via Vertex AI |

> **Note:** `roles/aiplatform.user` is only needed on your Vertex AI project — not on every project being scanned.

---

## Performance & Cost at Scale

### Cost Projection

| Component | Operations | Cost |
|---|---|---|
| Resource Manager API | 1 call to resolve all projects + numbers | Free |
| Cloud Run Admin API | 1 call per project (parallel) | Free |
| Cloud Logging API | 1 query per public service found (parallel) | Free |
| Risk classification | Pure Python per service | Free |
| Remediation templates | Jinja2 render per service | Free |
| **Gemini 2.5 Flash** | **1 call per run — flat** | **~$0.01–$0.05** |

**Total cost: under $0.05 per full org scan regardless of project count.**

### API Calls Per Run

| Scope | Fixed calls | Variable calls | Total |
|---|---|---|---|
| 1 project | 3 | +2 per public service | ~3–5 |
| 10 projects (folder) | 12 | +2 per public service | ~12–30 |
| 100 projects | 102 | +2 per public service | ~102+ |

Project number is now fetched alongside project ID in a single `search_projects` call — halving API usage compared to fetching project numbers separately.

### Performance Projection

| Projects | Workers | Estimated Scan Time |
|---|---|---|
| 10 | 10 | ~5 seconds |
| 100 | 10 | ~30 seconds |
| 500 | 10 | ~2.5 minutes |
| 1500 | 10 | ~7–8 minutes |
| 1500 | 20 | ~4 minutes |

Both Cloud Run scanning and traffic analysis run in parallel. The bottleneck is the Cloud Run scanning phase.

---

### API Quota Considerations

The Cloud Run Admin API has a default quota of **600 requests/minute**. At `MAX_WORKERS=10` scanning ~1500 projects, you may approach this limit.

**Recommended approach for large orgs:**

**Option 1 — Scan by folder (safest)**
```bash
python main.py --folder TEAM_A_FOLDER_ID
python main.py --folder TEAM_B_FOLDER_ID
```
This also produces per-team reports which are easier for team leads to action.

**Option 2 — Reduce workers**
```bash
# In .env
MAX_WORKERS=5
```

**Option 3 — Increase workers for trusted large orgs**
```bash
# In .env — increase to 20 workers if quota allows
# First check: GCP Console → APIs & Services → Cloud Run Admin API → Quotas
MAX_WORKERS=20
```

---

### Known Behaviours at Scale

| Scenario | Behaviour |
|---|---|
| Project has Cloud Run API disabled | Scanner logs a warning and skips — does not fail the run |
| Project has no Cloud Run services | Returns empty findings — counted in progress, excluded from report |
| Logging API unavailable for a service | Traffic classified as `Unknown` — still included in report with a warning |
| Gemini token limit exceeded (50+ findings) | Split scan by folder to reduce findings per report |
| `roles/aiplatform.user` missing on Vertex AI project | Clean error with exact fix instructions — no raw traceback |

---

## Dry Run Policy

**No changes are applied automatically.** All remediation output is `gcloud` commands for human review only. Always use `--dry-run` first when scanning a large scope to verify project count and estimated run time before proceeding.

---

## Roadmap

- [x] Phase 1 — Scaffold + Auth
- [x] Phase 2 — Cloud Run Scanner + Performance Guards
- [x] Phase 3 — Traffic Correlation (Cloud Logging API)
- [x] Phase 4 — Gemini 2.5 Flash Report + 6-Tier Risk Matrix + Remediation Templates
- [ ] Phase 5 — Natural language prompt parsing (filter by risk level, drill down on a specific service, remediation-only mode)
- [ ] Phase 6 — Per-folder report generation (one report per team/folder)
- [ ] Phase 7 — Schedule as Cloud Run Job (automated weekly scans)
- [ ] Phase 8 — Email/Slack notification for Critical and High findings
- [ ] Phase 9 — Multi-region parallel scanning optimisation

---

## License

MIT
