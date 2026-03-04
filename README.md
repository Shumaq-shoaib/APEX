# APEX — API Pentesting and Evaluation with Real-time eXamination  



> A unified, full-stack API security testing platform that systematically attacks REST APIs using both static specification analysis and live dynamic attack simulation — purpose-built for OWASP API Security Top 10 (2023).

---

## Table of Contents

1. [What is APEX?](#what-is-apex)
2. [How the Two Phases Work Together](#how-the-two-phases-work-together)
3. [Module 1: Static Analysis Engine](#module-1-static-analysis-engine)
4. [Module 2: Dynamic Attack Engine](#module-2-dynamic-attack-engine)
5. [Module 3: Frontend Dashboard](#module-3-frontend-dashboard)
6. [Module 4: Reporting System](#module-4-reporting-system)
7. [Project Structure](#project-structure)
8. [Quick Start](#quick-start)
9. [Usage Workflows](#usage-workflows)
10. [API Reference](#api-reference)
11. [Docker Services](#docker-services)
12. [Security Hardening](#security-hardening)
13. [Tech Stack](#tech-stack)
14. [Known Limitations](#known-limitations)

---

## What is APEX?

APEX is an automated API security scanner designed to find real vulnerabilities in REST APIs — not just flag theoretical issues against a checklist.

It operates in two phases that are tightly coupled:

- **Phase 1 — Static Analysis (SAST):** Parses and audits an OpenAPI 3.x specification file. Identifies design-level vulnerabilities, missing security controls, and risky patterns before the API is ever hit. Produces a structured **Blueprint** of all endpoints, methods, parameters, and security schemes.

- **Phase 2 — Dynamic Analysis (DAST):** Uses the Blueprint as input to drive live, authenticated attack campaigns against a running API. Each endpoint is tested by specialized attack scanners for injection, authorization bypass, authentication weaknesses, and more.

The key insight: **the Blueprint is the bridge**. Static analysis understands the API's shape; dynamic analysis uses that shape to attack it intelligently.

---

## How the Two Phases Work Together

```
┌─────────────────────────────────────────────────────────────────┐
│                        USER WORKFLOW                            │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                    Upload OpenAPI Spec
                     (.json / .yaml)
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│              MODULE 1: STATIC ANALYSIS ENGINE                   │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌───────────────────┐  │
│  │  OAS Parser  │───▶│  Rule Engine │──▶│ Blueprint Builder │  │
│  │  (v6_refactor│    │  (rules.py)  │    │  (blueprint.py)   │  │
│  │   /scanner.py│    │  70+ checks  │    │  Endpoint map     │  │
│  └──────────────┘    └──────────────┘    └─────────┬─────────┘  │
│                                                    │            │
│  Output: Static findings + Structured Blueprint    │            │
└────────────────────────────────────────────────────┼────────────┘
                                                     │
                               Blueprint (endpoints, params,
                                methods, auth schemes)
                                                     │
                                                     ▼
┌─────────────────────────────────────────────────────────────────┐
│              MODULE 2: DYNAMIC ATTACK ENGINE                    │
│                                                                 │
│  ┌──────────────────┐    ┌────────────────┐   ┌─────────────┐   │
│  │ Session          │───▶│ Attack Engine  │──▶│ 17 Scanners│   │
│  │ Orchestrator     │    │ (engine.py)    │   │ (see below) │   │
│  │ (orchestrator.py)│    │                │   │             │   │
│  └──────────────────┘    └────────────────┘   └──────┬──────┘   │
│                                                      │          │
│  Per endpoint: inject payloads, analyze responses,   │          │
│  record evidence, generate findings                  │          │
└──────────────────────────────────────────────────────┼──────────┘
                                                       │
                                                       ▼
                                           Findings + Evidence
                                          stored in MySQL DB
                                                        │
                                                        ▼
                                             HTML / PDF Report
```

---

## Module 1: Static Analysis Engine

**Location:** `static_analysis/src/v6_refactor/`

The static analysis engine audits OpenAPI specification files without making any network requests. It catches security issues at the design and contract level.

### How It Works

1. **Parse:** The `OasDetails` model (`models.py`) parses the raw OpenAPI JSON/YAML into a structured object exposing endpoints, parameters, schemas, security definitions, and server URLs.

2. **Analyze:** `scanner.py` iterates over all endpoint/method combinations and applies every rule function defined in `rules.py`. Rules check for:
   - Missing authentication (`securitySchemes`)
   - Weak JWT/OAuth configurations
   - Exposed sensitive data fields (PII, credentials, tokens)
   - Missing rate limiting indicators
   - Overly permissive CORS definitions
   - Insecure HTTP method usage
   - Unvalidated path/query parameters that accept arbitrary IDs (BOLA risk)
   - Missing input validation (`minLength`, `pattern`, `enum` on parameters)
   - Excessive data exposure (schemas returning more fields than needed)
   - Server URL configuration issues (HTTP, debug ports)

3. **Report:** `reporter.py` produces a structured findings report with severity, OWASP category, rule ID, and remediation guidance. The results are persisted to the database as a `StaticSpec` record.

4. **Blueprint:** `blueprint.py` extracts a machine-readable endpoint map from the parsed spec — listing every path, method, parameters (path/query/body), and expected response codes. This blueprint is stored alongside the findings and is fed directly into the Dynamic Engine.

### Static Analysis Features

| Feature | Description |
|---------|-------------|
| **70+ rules** | Comprehensive rule set in `rules.py` covering all OWASP API Top 10 (2023) categories |
| **Custom policy packs** | Upload a `.yaml` policy file to activate org-specific rule overrides |
| **Spectral integration** | Ingest a Spectral ruleset (`.yaml`) to extend the built-in rule engine |
| **Scan profiles** | `default`, `strict`, and custom profiles that control which rules are applied |
| **Blueprint generation** | Produces a structured endpoint map consumed by the Dynamic Engine |
| **Retention policy** | Automatically removes oldest scans when >20 stored specs |
| **Persistence** | All findings, metadata, and blueprints stored in MySQL for dashboard access |

### Static Analysis API

```
POST /api/specs                   Upload spec → run analysis → persist
GET  /api/specs                   List all past static scans
GET  /api/specs/{id}              Get full scan report + blueprint link
GET  /api/specs/{id}/blueprint    Get the endpoint Blueprint (JSON)
DELETE /api/specs/{id}            Delete spec and all associated data
```

---

## Module 2: Dynamic Attack Engine

**Location:** `apex-dynamic-service/app/`

The dynamic engine performs live security testing against a running API instance. It uses the Blueprint from static analysis to understand the target's structure, then runs 17 specialized attack scanners against every applicable endpoint.

### How It Works

1. **Session Creation:** A `DynamicTestSession` is created in the database, linked to a static `StaticSpec` (or a minimal placeholder spec for direct/quick scans). It stores the target URL, auth tokens, and current status.

2. **Orchestration:** `SessionOrchestrator` reads the blueprint, applies heuristic rules to decide which scanners are relevant for each endpoint/method combination, and creates `DynamicTestCase` records (one per scanner per endpoint).

3. **Execution:** `AttackEngine` loads all 17 scanners, iterates through test cases, and invokes each scanner's `run()` method with the endpoint, method, and parameter context.

4. **Context:** Each scanner receives a `ScanContext` object containing:
   - `target_url` — base URL of the API under test
   - `auth.token` — primary JWT (User A)
   - `auth.secondary_token` — secondary JWT (User B, for BOLA proof)
   - `scope` — list of paths in scope

5. **Evidence:** `HttpUtils.send_request_recorded()` captures every HTTP request and response, storing them as `DynamicFinding.evidence` for full audit trails.

### The 17 Native Scanners

| # | Scanner | OWASP Category | Severity Range |
|---|---------|---------------|----------------|
| 1 | **Active IDOR Scanner** | API1 — BOLA | Critical |
| 2 | **Passive IDOR Scanner** | API1 — BOLA | High |
| 3 | **JWT Security Scanner** | API2 — Broken Auth | Critical |
| 4 | **Broken Auth Scanner** | API2 — Broken Auth | Critical |
| 5 | **Mass Assignment Scanner** | API3 — Broken Object Property Level Auth | High |
| 6 | **SQLi / NoSQLi Scanner** | API8 — Injection | Critical |
| 7 | **Command Injection Scanner** | API8 — Injection | Critical |
| 8 | **SSRF Scanner** | API7 — SSRF | Critical |
| 9 | **SSTI Scanner** | API8 — Injection | Critical |
| 10 | **XSS Scanner** | API8 — Security Misconfiguration | High |
| 11 | **CORS Scanner** | API8 — Security Misconfiguration | High |
| 12 | **CSRF Scanner** | API8 — Security Misconfiguration | High |
| 13 | **CRLF Injection Scanner** | API8 — Security Misconfiguration | Medium |
| 14 | **Rate Limiting Scanner** | API4 — Unrestricted Resource Consumption | High |
| 15 | **Security Headers Scanner** | API8 — Security Misconfiguration | Medium |
| 16 | **Open Redirect Scanner** | API8 — Security Misconfiguration | Medium |
| 17 | **XXE Scanner** | API8 — Injection | High |

### Key Scanner Capabilities

**BOLA/IDOR — Automated Token Swapping:**
The Active IDOR Scanner makes a baseline request as User A (primary token), then replays the exact same request as User B (secondary token). If User B receives `200 OK` with identical response data, it is flagged as a **Critical BOLA** — a mathematically proven authorization bypass.

**SSRF — Content Reflection Required:**
SSRF is only flagged when the response body contains identifiable content from the injected target (e.g., `<title>crAPI</title>` or `response_from_mechanic_api`). A simple `200 OK` is *not* sufficient — this eliminates false positives.

**JWT Attacks:**
- `alg: none` — strips the signature algorithm to bypass verification
- Signature exclusion — replaces signature with an empty string

**NoSQL Injection:**
MongoDB operator payloads: `{"$ne": null}`, `{"$gt": ""}`, `{"$nin": []}`, `{"$where": "1==1"}`

**Mass Assignment:**
Injects sensitive fields into request bodies: `isAdmin`, `role`, `credit`, `available_credit`, `mechanic_code`, `mechanic_api`

### Dynamic Scan Modes

| Mode | Endpoint | Description |
|------|----------|-------------|
| **Standard** | `POST /api/sessions` | Create session from existing static spec ID |
| **Direct** | `POST /api/sessions/direct` | Upload spec + auto-start scan in one request |
| **Quick** | `POST /api/sessions/quick` | Scan by URL only (no spec required, heuristic discovery) |

---

## Module 3: Frontend Dashboard

**Location:** `frontend/dashboard/`

A React + TypeScript single-page application for managing and visualizing APEX scans.

### Pages

| Page | Purpose |
|------|---------|
| **Static Analysis** | Upload an OpenAPI spec, view the rule-based findings report, and initiate a dynamic scan from the result |
| **Dynamic Analysis** | Configure a new scan session (target URL, auth tokens), monitor status, view live findings as they arrive |
| **History** | Browse all past static and dynamic scans, view their findings |
| **Reports** | Download HTML or PDF reports for completed sessions |

### Dashboard → Static → Dynamic Flow

1. User uploads spec on the **Static Analysis** page
2. APEX runs the rule engine and shows findings immediately
3. A "Start Dynamic Scan" button appears — pre-populated with the spec blueprint
4. User adds the target URL and auth tokens, then launches the dynamic scan
5. The **Dynamic Analysis** page polls for live findings
6. On completion, the **Reports** page lets the user download the full report

---

## Module 4: Reporting System

**Location:** `apex-dynamic-service/app/services/reporting.py` and `report_generator.py`

Each finding includes:

| Field | Description |
|-------|-------------|
| **Title** | Short vulnerability name |
| **Description** | What was detected and why it's dangerous |
| **Severity** | Critical / High / Medium / Low / Informational |
| **CVSS Score** | Numeric risk score (0.0–10.0) |
| **OWASP Category** | Mapped to API Security Top 10 (2023) |
| **Check Type** | Internal classification (BOLA, SQLI, SSRF, etc.) |
| **Endpoint + Method** | Exact location of the vulnerability |
| **Remediation** | Actionable fix guidance |
| **Request Dump** | Full HTTP request sent by the scanner |
| **Response Dump** | Full HTTP response received |

**Download formats:**
```bash
# HTML (view in browser)
GET /api/sessions/{session_id}/report?format=html

# PDF (for submission/archiving)
GET /api/sessions/{session_id}/report?format=pdf
```

---

## Project Structure

```
APEX-main/
│
├── apex-dynamic-service/              ← FastAPI backend (all server-side logic)
│   ├── app/
│   │   ├── api/
│   │   │   ├── deps.py                ← DB dependency injection
│   │   │   └── routes/
│   │   │       ├── specs.py           ← Static analysis endpoints
│   │   │       └── sessions.py        ← Dynamic scan session endpoints
│   │   ├── core/
│   │   │   ├── config.py              ← App settings (DB URL, CORS, version)
│   │   │   ├── limiter.py             ← Rate limiting (slowapi)
│   │   │   └── logging.py             ← Structured JSON logging
│   │   ├── db/
│   │   │   ├── base.py                ← SQLAlchemy declarative base
│   │   │   └── session.py             ← Engine factory + SessionLocal
│   │   ├── models/
│   │   │   └── dynamic.py             ← ORM: StaticSpec, DynamicTestSession,
│   │   │                                        DynamicTestCase, DynamicFinding,
│   │   │                                        DynamicEvidence
│   │   ├── scanner_core/
│   │   │   └── context.py             ← ScanContext (target, auth, scope)
│   │   ├── scanner_utils/
│   │   │   ├── payloads.py            ← Central payload library (all attack strings)
│   │   │   ├── detection.py           ← Response analysis patterns
│   │   │   └── http.py                ← HTTP client with request/response recording
│   │   ├── scanners/
│   │   │   ├── base.py                ← BaseScanner abstract class
│   │   │   ├── bola.py                ← Passive IDOR
│   │   │   ├── idor_active.py         ← Active IDOR + token swapping
│   │   │   ├── jwt_scan.py            ← JWT None alg + sig exclusion
│   │   │   ├── broken_auth.py         ← Auth bypass heuristics
│   │   │   ├── ssrf.py                ← SSRF (metadata + internal)
│   │   │   ├── injection_sqli.py      ← SQL + NoSQL injection
│   │   │   ├── injection_cmd.py       ← OS command injection
│   │   │   ├── mass_assignment.py     ← Property injection
│   │   │   ├── xss.py                 ← Reflected XSS
│   │   │   ├── ssti.py                ← Template injection
│   │   │   ├── cors.py                ← CORS misconfiguration
│   │   │   ├── csrf.py                ← CSRF token absence
│   │   │   ├── crlf.py                ← CRLF/header injection
│   │   │   ├── rate_limit.py          ← Rate limit absence
│   │   │   ├── headers.py             ← Security headers audit
│   │   │   ├── redirect.py            ← Open redirect
│   │   │   └── xxe.py                 ← XXE injection
│   │   └── services/
│   │       ├── engine.py              ← AttackEngine (loads + runs scanners)
│   │       ├── orchestrator.py        ← SessionOrchestrator (heuristics + scheduling)
│   │       ├── direct_parser.py       ← OAS parser for direct/quick scans
│   │       ├── reporting.py           ← CVSS scoring + remediation content
│   │       └── report_generator.py    ← HTML/PDF report rendering
│   ├── alembic/                       ← DB migrations
│   └── Dockerfile
│
├── static_analysis/                   ← SAST engine (Python, mounted into backend)
│   ├── src/v6_refactor/
│   │   ├── scanner.py                 ← Main analysis entry point
│   │   ├── rules.py                   ← 70+ rule functions
│   │   ├── blueprint.py               ← Endpoint blueprint generator
│   │   ├── reporter.py                ← Findings + report formatter
│   │   ├── models.py                  ← OasDetails (spec parser)
│   │   ├── config.py                  ← Scan profiles and settings
│   │   ├── helpers.py                 ← Schema traversal + resolution utilities
│   │   ├── utils.py                   ← General parsing utilities
│   │   └── cli.py                     ← Optional CLI interface
│   ├── api/                           ← OpenAPI spec samples
│   ├── packs/                         ← Custom policy packs
│   └── rules/                         ← YAML rule definitions
│
├── frontend/dashboard/                ← React SPA
│   ├── src/
│   │   ├── components/dashboard/      ← Scan panels, findings tables
│   │   ├── components/layout/         ← Sidebar + shell
│   │   ├── components/ui/             ← shadcn/ui primitives
│   │   ├── pages/                     ← Routed pages (Static, Dynamic, History)
│   │   ├── lib/                       ← API client, config, helpers
│   │   └── types/                     ← TypeScript shared types
│   ├── Dockerfile                     ← Dev container (HMR)
│   └── Dockerfile.prod                ← Production multi-stage Nginx build
│
├── scripts/                           ← Utility and maintenance scripts
├── tests/                             ← Verification test scripts
├── docs/plans/                        ← Implementation plans + task tracker
├── docker-compose.yml
└── requirements.txt
```

---

## Quick Start

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (required)
- Node.js 18+ *(optional, for local frontend development only)*

### 1. Start APEX

```bash
cd APEX-main
docker compose up -d --build
```

| Service | URL | Notes |
|---------|-----|-------|
| **Dashboard** | http://localhost:5173 | React dev server |
| **Backend API** | http://localhost:8000/docs | Swagger UI |
| **Health Check** | http://localhost:8000/health | DB + scanner status |

### 2. (Optional) Start crAPI Target

[crAPI](https://github.com/OWASP/crAPI) is an intentionally vulnerable API — the recommended target for testing APEX.

```bash
cd "API deployment"
docker compose up -d
```

crAPI base URL: `http://localhost:8888`

---

## Usage Workflows

### Workflow A: Static + Dynamic (Recommended)

**Best for:** When you have an OpenAPI spec and want thorough coverage.

1. Open the Dashboard → **Static Analysis**
2. Upload your OpenAPI spec (`.json` or `.yaml`)
3. Review static findings (authentication gaps, missing validation, BOLA risks)
4. Click **"Start Dynamic Scan"** — the blueprint auto-populates
5. Enter the target URL and auth Bearer token(s)
6. (Optional) Enter a **secondary token** from a different user account for BOLA/IDOR cross-user testing
7. Run scan — monitor findings in the **Dynamic Analysis** view
8. Download HTML or PDF report when complete

### Workflow B: Direct Scan (Single Step)

**Best for:** When you want to skip the dashboard and automate via API.

```bash
# Create users on crAPI first (if using crAPI)
# Then submit the scan directly:

curl -X POST http://localhost:8000/api/sessions/direct \
  -F "file=@path/to/openapi.json" \
  -F "target_url=http://localhost:8888" \
  -F "auth_token=Bearer <USER_A_JWT>" \
  -F "auth_token_secondary=Bearer <USER_B_JWT>"

# Returns session ID. Poll for results:
curl http://localhost:8000/api/sessions/<session_id>

# Download report when status == COMPLETED:
curl "http://localhost:8000/api/sessions/<session_id>/report?format=pdf" -o report.pdf
```

### Workflow C: Quick Scan (No Spec)

**Best for:** Rapid heuristic scanning when you only have a URL.

```bash
curl -X POST http://localhost:8000/api/sessions/quick \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://localhost:8888", "auth_token": "Bearer <JWT>"}'
```

### Workflow D: Static Analysis Only (CLI)

```bash
cd static_analysis
python -m v6_refactor scan --spec path/to/openapi.json --profile strict
```

---

## API Reference

### Specs (Static Analysis)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/specs` | Upload + analyze OpenAPI spec |
| `GET` | `/api/specs` | List all past static scans |
| `GET` | `/api/specs/{id}` | Get full scan report |
| `GET` | `/api/specs/{id}/blueprint` | Get endpoint blueprint |
| `DELETE` | `/api/specs/{id}` | Delete spec and all data |

### Sessions (Dynamic Analysis)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/sessions` | Create session from existing spec ID |
| `POST` | `/api/sessions/direct` | Upload spec + auto-start scan |
| `POST` | `/api/sessions/quick` | Scan by URL only |
| `POST` | `/api/sessions/{id}/start` | Start a PENDING session |
| `GET` | `/api/sessions/{id}` | Get status, findings, test cases |
| `GET` | `/api/sessions/{id}/report` | Download HTML/PDF report |

### Utility

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Backend + DB health status |
| `GET` | `/docs` | Interactive Swagger UI |

---

## Docker Services

| Service | Container | Port | Profile | Description |
|---------|-----------|------|---------|-------------|
| `backend` | `apex-backend` | `8000` | default | FastAPI + scanner engine |
| `frontend` | `apex-frontend` | `5173` | default | React dev server (HMR) |
| `frontend-prod` | `apex-frontend-prod` | `80` | `prod` | Nginx production build |
| `db` | `apex-db` | `3306` | default | MySQL 8.0 |

**Start dev stack:**
```bash
docker compose up -d
```

**Start production frontend:**
```bash
docker compose --profile prod up -d --build frontend-prod
```

**View backend logs:**
```bash
docker logs -f apex-backend
```

---

## Security Hardening

| Feature | Implementation |
|---------|---------------|
| **CORS allowlist** | `ALLOWED_ORIGINS` config via `CORSMiddleware` |
| **Rate limiting** | slowapi — 2/min on scan endpoints, 10/min on sessions |
| **Upload validation** | Extension whitelist (`.json`, `.yaml`, `.yml`) + 10 MB size cap |
| **Request validation** | Pydantic models + `HttpUrl` type enforcement |
| **Structured logging** | JSON-format logs with session/scanner/module context |
| **DB health checks** | MySQL `mysqladmin ping` with retry logic on container start |
| **Auto-restart** | Backend container `restart: always` for resilience |
| **Retention policy** | Auto-deletes scans beyond the last 20 |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.10, FastAPI, SQLAlchemy, Pydantic v2 |
| Static Engine | Custom rule engine (Python), Spectral-compatible |
| HTTP Client | `httpx` (sync, used inside scanner threads) |
| Database | MySQL 8.0, Alembic migrations |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, shadcn/ui |
| Containers | Docker, Docker Compose |
| Rate Limiting | slowapi |
| Reports | Jinja2 (HTML), WeasyPrint (PDF) |

---

## Known Limitations

| Area | Limitation |
|------|-----------|
| **Auth** | No user authentication for the APEX dashboard itself |
| **Rate limiter** | In-memory storage — resets on restart. Use Redis for production |
| **Real-time** | Scan progress via polling (no WebSocket/SSE) |
| **BOLA token swap** | Uses a hardcoded fallback resource ID as a starting point |
| **Frontend tests** | Baseline Vitest tests only — no full E2E suite |

---

*APEX — Final Year Project*
