# gcp-security-agent

A GCP security agent that autonomously identifies public exposure risks across **Cloud Run Services** and **Cloud Functions (Gen 1 + Gen 2)**, classifies them against a structured risk matrix, and generates remediation steps. Built with Python, Vertex AI (Gemini 2.5 Flash), and GCP-native tooling. Scales from a single project to an entire GCP organization.

---

## What It Does

1. **Resolves** target projects — single project, folder, or entire org
2. **Scans** Cloud Run Services + Cloud Functions Gen 1 and Gen 2 in parallel
3. **Flags** Gen 1 functions for migration to Gen 2 with official Google documentation links
4. **Estimates** cost and scope before running (dry-run mode)
5. **Correlates** traffic logs via Cloud Logging API to enrich findings
6. **Classifies** each service against an 11-tier risk matrix — pure Python, zero LLM cost
7. **Generates** ready-to-copy `gcloud` remediation commands per risk category and resource type — zero LLM cost
8. **Synthesizes** a single Gemini 2.5 Flash call to produce a narrative markdown report

---

## Architecture

```
CLI Input (--project | --folder | --org | --resource)
          │
          ▼
  project_resolver.py          ← GCP Resource Manager API
          │
          ▼
  [--max-projects cap]
          │
          ▼
  ThreadPoolExecutor            ← parallel scan (10 workers)
  ┌────────────────────────┐
  │ cloud_run_scanner.py   │   ← Cloud Run Admin API (Services)
  │ cloud_functions_       │   ← Cloud Functions API v1 (Gen 1)
  │   scanner.py           │   ← Cloud Functions API v2 (Gen 2)
  └────────────────────────┘
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
          │      ▲
          │      └── routes to CR or CF templates by resource_type
          │      └── Gen 1 findings always include migration warning block
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
- ❌ Determine ingress/auth/SA issues — handled by scanner modules
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
| `config/risk_matrix.md` | Single source of truth for risk classification logic. Read by `risk_classifier.py` and injected into Gemini system prompt. Update this file to evolve security standards — no code changes needed. | No |
| `tools/risk_classifier.py` | Pure Python 11-tier risk classifier. Reads ingress, auth, SA, and traffic data and assigns a risk category. Same logic applies to Cloud Run and Cloud Functions. | No |
| `tools/remediation_templates.py` | Jinja2 templates generating ready-to-copy `gcloud` fix commands. Routes to Cloud Run or Cloud Functions templates by `resource_type`. Gen 1 findings always include migration warning block. | No |
| `agent/orchestrator.py` | The only file that calls Gemini. One API call per run. Authenticated using `--vertex-project` or `PROJECT_ID` in `.env`. | ✅ Yes — once |
| `tools/cloud_run_scanner.py` | Scans Cloud Run Services via Cloud Run Admin API v2. Extracts ingress, IAM, and SA config. | No |
| `tools/cloud_functions_scanner.py` | Scans Cloud Functions Gen 1 (functions_v1 SDK) and Gen 2 (functions_v2 SDK). Normalises ingress enums to match Cloud Run values so the same risk matrix applies. Flags Gen 1 for migration. | No |
| `tools/traffic_analyzer.py` | Queries Cloud Logging API for request counts. Runs in parallel. Classifies Active or Inactive. | No |
| `tools/project_resolver.py` | Resolves project/folder/org scope into flat list of active projects with `project_id` + `project_number` in a single API call. | No |
| `tools/cost_estimator.py` | Dry-run scope summary — project count, findings count, estimated run time. | No |
| `config/settings.py` | Loads all environment variables from `.env`. Single config source. | No |
| `main.py` | CLI entry point. Orchestrates full pipeline. Separates scan scope from Vertex AI auth. Supports `--resource` flag to filter resource types. | No |

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.11+ |
| LLM | Gemini 2.5 Flash (Vertex AI) — single call per run |
| Risk Classification | Pure Python against `config/risk_matrix.md` |
| Remediation Commands | Jinja2 templates per risk category + resource type |
| Cloud Run Discovery | Google Cloud Run v2 Python SDK |
| Cloud Functions Discovery | Google Cloud Functions v1 + v2 Python SDK |
| Traffic Analysis | Google Cloud Logging Python SDK |
| Project Resolution | Google Cloud Resource Manager v3 SDK |
| Concurrency | Python `concurrent.futures` (stdlib) |
| Auth | GCP Application Default Credentials (ADC) |
| IDE | Google Antigravity |

---

## Supported Resource Types

| Resource | API | Gen | Scanned |
|---|---|---|---|
| Cloud Run Services | `run.googleapis.com` v2 | N/A | ✅ |
| Cloud Functions | `cloudfunctions.googleapis.com` | Gen 1 | ✅ + migration warning |
| Cloud Functions | `cloudfunctions.googleapis.com` | Gen 2 | ✅ |
| Cloud Run Jobs | `run.googleapis.com` | N/A | ❌ Roadmap Phase 6 |

### Cloud Functions Gen 1 — Migration Warning

Every Gen 1 function finding includes a `⚠️ GEN 1 MIGRATION REQUIRED` block in its remediation output:

```
⚠️  GEN 1 FUNCTION — MIGRATION TO GEN 2 REQUIRED
Cloud Functions Gen 1 is legacy infrastructure.
Migration guide: https://cloud.google.com/functions/docs/migrating
Gen 2 overview: https://cloud.google.com/functions/docs/concepts/version-comparison
```

Gen 1 is flagged regardless of risk level — even `Minimal: Zero Trust` Gen 1 functions receive the migration notice.

---

## Risk Matrix (11-Tier)

| Category | Ingress | Auth | Traffic | Risk Level |
|---|---|---|---|---|
| Critical: Exposed & Abandoned | all | ❌ | 0 | Critical |
| High: Public Direct Access | all | ❌ | >0 | High |
| High: LB Exposed & Abandoned | LB | ❌ | 0 | High |
| Medium: LB Unauthenticated | LB | ❌ | >0 | Medium |
| Medium: Identity Leakage | all | ✅ | any | Medium |
| Medium: Identity Leakage (LB) | LB | ✅ (default SA) | any | Medium |
| Medium: LB Bypass Risk | all | ✅ | any | Medium |
| Low: Shielded | LB | ✅ | any | Low |
| Low: Internal Exposed (Abandoned) | internal | ❌ | 0 | Low |
| Low: Internal Unauthenticated | internal | ❌ | >0 | Low |
| Minimal: Zero Trust | internal | ✅ | any | Minimal |

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
├── main.py                           ← CLI entry point + pipeline orchestration
├── config/
│   ├── settings.py                   ← env var loader (single source of config)
│   └── risk_matrix.md                ← risk classification logic (single source of truth)
├── tools/
│   ├── __init__.py
│   ├── project_resolver.py           ← resolves project list + project numbers
│   ├── cloud_run_scanner.py          ← discovers public Cloud Run Services
│   ├── cloud_functions_scanner.py    ← discovers public Cloud Functions Gen1 + Gen2
│   ├── traffic_analyzer.py           ← Cloud Logging traffic correlation (parallel)
│   ├── risk_classifier.py            ← deterministic 11-tier Python risk classification
│   ├── cost_estimator.py             ← dry-run scope + run time estimation
│   └── remediation_templates.py      ← Jinja2 gcloud fix commands (CR + CF routing)
├── agent/
│   └── orchestrator.py               ← single Gemini 2.5 Flash report synthesis call
└── output/                           ← generated reports (gitignored)
```

---

## Setup

### Prerequisites
- Python 3.11+
- GCP project with Vertex AI enabled
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
  cloudfunctions.googleapis.com \
  logging.googleapis.com \
  cloudresourcemanager.googleapis.com \
  aiplatform.googleapis.com \
  --project YOUR_PROJECT_ID
```

---

## Usage

```bash
# Scan everything — Cloud Run Services + Cloud Functions Gen1 + Gen2 (default)
python main.py --project my-project

# Cloud Functions only
python main.py --project my-project --resource cloud-functions

# Cloud Run Services only
python main.py --project my-project --resource cloud-run

# All projects in a folder
python main.py --folder 123456789

# Entire org
python main.py --org 987654321

# Dry run — estimate scope first (recommended before large scans)
python main.py --org 987654321 --dry-run

# Cap projects for safe testing
python main.py --org 987654321 --max-projects 10

# Scan a company project using a different project for Gemini auth
python main.py --project company-project --vertex-project my-personal-project

# With custom prompt
python main.py --project my-project --prompt "Analyze all public exposure risks"
```

---

## Project ID Separation — Scan Target vs Vertex AI Auth

Two project IDs serve different purposes and are intentionally independent:

| Setting | Purpose | Where to set |
|---|---|---|
| `--project` / `--folder` / `--org` | **Scan target** — what gets scanned | CLI flag |
| `PROJECT_ID` in `.env` | **Vertex AI auth** — which project authenticates Gemini | `.env` file |
| `--vertex-project` | **Vertex AI auth override** — overrides `PROJECT_ID` for a single run | CLI flag |

```bash
# Scan company project, authenticate Gemini via personal project
python main.py \
  --project company-project-id \
  --vertex-project my-personal-project
```

### Required IAM roles

| Role | Project | Purpose |
|---|---|---|
| `roles/run.viewer` | Scan target project(s) | List Cloud Run Services |
| `roles/cloudfunctions.viewer` | Scan target project(s) | List Cloud Functions |
| `roles/logging.viewer` | Scan target project(s) | Read Cloud Logging |
| `roles/resourcemanager.folderViewer` | Folder (if using --folder) | List projects under folder |
| `roles/resourcemanager.organizationViewer` | Org (if using --org) | List all org projects |
| `roles/aiplatform.user` | **Vertex AI project only** | Call Gemini via Vertex AI |

> `roles/aiplatform.user` is only needed on your Vertex AI project — not on every project being scanned.

---

## Performance & Cost at Scale

### Cost Projection

| Component | Operations | Cost |
|---|---|---|
| Resource Manager API | 1 call to resolve all projects + numbers | Free |
| Cloud Run Admin API | 1 call per project (parallel) | Free |
| Cloud Functions API | 2 calls per project — Gen1 + Gen2 (parallel) | Free |
| Cloud Logging API | 1 query per public finding (parallel) | Free |
| Risk classification | Pure Python per finding | Free |
| Remediation templates | Jinja2 render per finding | Free |
| **Gemini 2.5 Flash** | **1 call per run — flat** | **~$0.01–$0.05** |

**Total cost: under $0.05 per full org scan regardless of project or finding count.**

### API Calls Per Run

| Scope | Fixed calls | Variable calls | Total |
|---|---|---|---|
| 1 project (all resources) | 5 | +2 per public finding | ~5–15 |
| 10 projects (folder) | 32 | +2 per public finding | ~32–60 |
| 100 projects | 302 | +2 per public finding | ~302+ |

### Performance Projection

| Projects | Workers | Estimated Scan Time |
|---|---|---|
| 10 | 10 | ~10 seconds |
| 100 | 10 | ~1 minute |
| 500 | 10 | ~5 minutes |
| 1500 | 10 | ~12–15 minutes |
| 1500 | 20 | ~7 minutes |

Cloud Functions scanning adds ~2 API calls per project vs Cloud Run only. Traffic analysis runs in parallel and adds less than 30 seconds regardless of finding count.

---

### API Quota Considerations

| API | Default Quota | Risk at Scale |
|---|---|---|
| Cloud Run Admin API | 600 req/min | Medium — 1500 projects at MAX_WORKERS=10 may approach limit |
| Cloud Functions API | 600 req/min | Medium — same pattern |
| Cloud Logging API | 60 req/min | Low — only called for public findings |

**Recommended approach for large orgs:**

```bash
# Scan by folder — safest, produces per-team reports
python main.py --folder TEAM_A_FOLDER_ID
python main.py --folder TEAM_B_FOLDER_ID

# Or reduce workers in .env
MAX_WORKERS=5
```

---

### Known Behaviours at Scale

| Scenario | Behaviour |
|---|---|
| Project has Cloud Run API disabled | Scanner logs warning and skips — does not fail the run |
| Project has Cloud Functions API disabled | Scanner logs warning and skips — does not fail the run |
| Project has no public services or functions | Returns empty findings — excluded from report |
| Logging API unavailable | Traffic classified as `Unknown` — still included in report |
| Gen 1 function found (any risk level) | Migration warning block added to remediation output |
| Gemini token limit exceeded (50+ findings) | Split scan by folder to reduce findings per report |
| `roles/aiplatform.user` missing | Clean error with exact fix instructions — no raw traceback |

---

## Dry Run Policy

**No changes are applied automatically.** All remediation output is `gcloud` commands for human review only. Always use `--dry-run` first when scanning a large scope.

---

## Roadmap

- [x] Phase 1 — Scaffold + Auth
- [x] Phase 2 — Cloud Run Scanner + Performance Guards
- [x] Phase 3 — Traffic Correlation (Cloud Logging API)
- [x] Phase 4 — Gemini 2.5 Flash Report + 11-Tier Risk Matrix + Remediation Templates
- [x] Phase 5 — Cloud Functions Gen 1 + Gen 2 Scanner + Gen 1 Migration Warning
- [ ] Phase 6 — Natural language prompt parsing (filter by risk level, drill down on specific service)
- [ ] Phase 7 — Per-folder report generation (one report per team/folder)
- [ ] Phase 8 — Schedule as Cloud Run Job (automated weekly scans)
- [ ] Phase 9 — Email/Slack notification for Critical and High findings
- [ ] Phase 10 — Multi-region parallel scanning optimisation

---

## License

MIT
