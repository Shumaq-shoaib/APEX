# APEX — API Penetration & Exploitation eXaminer

> A unified, full-stack API security testing platform combining Static Analysis (SAST) and Dynamic Attack Simulation (DAST) in a single native engine.

---

## Overview

APEX is purpose-built for automated API security testing against REST APIs described by OpenAPI 3.x specifications. It provides:

- **Static Analysis (SAST):** Rule-based scanning of OpenAPI spec files to surface design-level vulnerabilities before deployment.
- **Dynamic Analysis (DAST):** Live, authenticated attack simulation against running API endpoints using a native, unified scanner engine.
- **A React Dashboard:** Real-time scan management, findings visualization, and report generation in the browser.

APEX was developed as an academic Final Year Project (FYP) targeting the [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x00-header/).

---

## Architecture

```
APEX-main/
├── apex-dynamic-service/        ← FastAPI backend (API + Scanner Engine)
│   └── app/
│       ├── api/routes/          ← REST endpoints: /api/specs, /api/sessions
│       ├── scanner_core/        ← ScanContext, AuthConfig (token + secondary token)
│       ├── scanner_utils/       ← PayloadLibrary, DetectionUtils, HttpUtils
│       ├── scanners/            ← 17 native attack scanners (see below)
│       ├── services/            ← AttackEngine, SessionOrchestrator, ReportManager
│       ├── models/              ← SQLAlchemy models (sessions, findings, evidence)
│       └── core/                ← Config, logging, rate limiter
├── frontend/dashboard/          ← React + Vite + TypeScript dashboard
├── static_analysis/             ← SAST engine (OpenAPI rule evaluator + blueprint generator)
├── scripts/                     ← Utility scripts
├── tests/                       ← Backend verification tests
└── docker-compose.yml
```

**Database:** MySQL 8.0 (`apex-db` container) stores all specs, sessions, test cases, findings, and request/response evidence.

---

## Native Scanner Engine

APEX runs **17 native attack scanners** — all implemented as first-class Python modules with zero external ZAP/Astra dependencies.

| Scanner | OWASP Category | Check Type |
|---------|---------------|-----------|
| Active IDOR Scanner | API1 — Broken Object Level Authorization | `BOLA` |
| Passive IDOR Scanner | API1 — Broken Object Level Authorization | `BOLA` |
| JWT Security Scanner | API2 — Broken Authentication | `BROKEN_AUTH` |
| Broken Auth Scanner | API2 — Broken Authentication | `BROKEN_AUTH` |
| Mass Assignment Scanner | API3 — Broken Object Property Level Authorization | `DATA_EXPOSURE` |
| SQLi/NoSQLi Scanner | API8 — Security Misconfiguration (Injection) | `SQLI` |
| Command Injection Scanner | API8 — Security Misconfiguration (Injection) | `INJECTION` |
| SSRF Scanner | API7 — Server-Side Request Forgery | `SSRF` |
| SSTI Scanner | API8 — Security Misconfiguration | `SSTI` |
| XSS Scanner | API8 — Security Misconfiguration | `XSS` |
| CORS Scanner | API8 — Security Misconfiguration | `CORS` |
| CSRF Scanner | API8 — Security Misconfiguration | `CSRF` |
| CRLF Injection Scanner | API8 — Security Misconfiguration | `CRLF` |
| Rate Limiting Scanner | API4 — Unrestricted Resource Consumption | `RATE_LIMIT` |
| Security Headers Scanner | API8 — Security Misconfiguration | `BROKEN_AUTH` |
| Open Redirect Scanner | API8 — Security Misconfiguration | `OTHER` |
| XXE Scanner | API8 — Security Misconfiguration | `OTHER` |

### Key Detection Capabilities

- **JWT Attacks:** None algorithm, signature exclusion
- **BOLA/IDOR Proof:** Automated token swapping — User B's token is used to access User A's resources; identical responses prove cross-user data leakage (Critical BOLA)
- **SSRF:** Cloud metadata probing (AWS/GCP/Azure/Alibaba), internal network access — requires actual content reflection, not just HTTP 200
- **NoSQLi:** MongoDB operator injection (`$ne`, `$gt`, `$nin`, `$where`)
- **Mass Assignment:** Sensitive property injection (`isAdmin`, `role`, `credit`, `available_credit`, `mechanic_code`)
- **SSTI:** Multi-engine template injection (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`)
- **XSS:** Reflected XSS in URL path, query parameters, HTTP headers, and JSON body fields

---

## Quick Start

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- (Optional) Node.js 18+ for local frontend development
- (Optional) Python 3.10+ for local script execution

### 1. Start APEX

```bash
cd APEX-main
docker compose up -d --build
```

| Service | URL |
|---------|-----|
| React Dashboard | http://localhost:5173 |
| Backend API (Swagger UI) | http://localhost:8000/docs |
| Backend Health Check | http://localhost:8000/health |

### 2. (Optional) Start a Target API

APEX works best against a real API. For testing, use [crAPI (Completely Ridiculous API)](https://github.com/OWASP/crAPI):

```bash
cd "API deployment"
docker compose up -d
```

crAPI target URL: `http://localhost:8888`

### 3. Run a Static Analysis

1. Navigate to the Dashboard → **Static Analysis**
2. Upload your OpenAPI 3.x spec (`.json` or `.yaml`)
3. View the rule-based findings and generated blueprint

### 4. Run a Dynamic Scan

**Via Dashboard:**
1. Navigate to **Dynamic Analysis**
2. Upload your spec file, set the target URL and Bearer token
3. Optionally provide a **secondary token** (for BOLA/IDOR cross-user testing)
4. Start scan and monitor live findings

**Via API (direct):**
```bash
curl -X POST http://localhost:8000/api/sessions/direct \
  -F "file=@path/to/openapi.json" \
  -F "target_url=http://localhost:8888" \
  -F "auth_token=Bearer <your_jwt_token>" \
  -F "auth_token_secondary=Bearer <second_user_jwt>"
```

**Response:** Returns a session ID. Poll for results:
```bash
curl http://localhost:8000/api/sessions/<session_id>
```

---

## Authentication in Dynamic Scans

APEX supports two authentication tokens per scan session for full BOLA/IDOR coverage:

| Field | Purpose |
|-------|---------|
| `auth_token` | Primary user JWT (Bearer) — used for baseline requests |
| `auth_token_secondary` | Secondary user JWT — used by the IDOR scanner to prove cross-user access |

The Active IDOR Scanner automatically performs **token swapping**: it requests an endpoint as User A, then replays the exact same request as User B. If User B gets a 200 OK with identical data, it is reported as a **Critical BOLA vulnerability**.

---

## Report Generation

APEX generates downloadable reports for completed scan sessions:

```bash
# HTML report
curl http://localhost:8000/api/sessions/<session_id>/report?format=html -o report.html

# PDF report
curl http://localhost:8000/api/sessions/<session_id>/report?format=pdf -o report.pdf
```

Each finding includes:
- Vulnerability title and OWASP category
- Severity (Critical / High / Medium / Low / Info)
- CVSS score
- Remediation guidance
- Full request/response evidence dump

---

## Backend API Reference

All endpoints are documented interactively at `http://localhost:8000/docs`.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/specs` | Upload and run static analysis on an OpenAPI spec |
| `GET` | `/api/specs/{id}` | Retrieve static analysis results |
| `POST` | `/api/sessions` | Create a dynamic scan session (spec required) |
| `POST` | `/api/sessions/direct` | Create + auto-start scan from uploaded spec file |
| `POST` | `/api/sessions/quick` | Start a scan with target URL only (no spec) |
| `POST` | `/api/sessions/{id}/start` | Start a pending session |
| `GET` | `/api/sessions/{id}` | Get session status, findings, and test cases |
| `GET` | `/api/sessions/{id}/report` | Download HTML or PDF report |
| `GET` | `/health` | Health check (database + scanner status) |

---

## Project Structure (Detailed)

```
apex-dynamic-service/app/
├── api/
│   ├── deps.py                  ← DB dependency injection
│   └── routes/
│       ├── sessions.py          ← Dynamic scan session management
│       └── specs.py             ← Static spec upload and analysis
├── core/
│   ├── config.py                ← Settings (DB URL, CORS origins, version)
│   ├── limiter.py               ← Rate limiting (slowapi)
│   └── logging.py               ← Structured JSON logging
├── db/
│   ├── base.py                  ← SQLAlchemy declarative base
│   └── session.py               ← Engine + SessionLocal factory
├── models/
│   └── dynamic.py               ← ORM models: sessions, test cases, findings, evidence
├── scanner_core/
│   └── context.py               ← ScanContext (target URL, auth tokens, scope)
├── scanner_utils/
│   ├── payloads.py              ← Unified payload library (SQLi, XSS, SSRF, SSTI, etc.)
│   ├── detection.py             ← Detection patterns and regex matchers
│   └── http.py                  ← HttpUtils (request recording, evidence capture)
├── scanners/
│   ├── base.py                  ← BaseScanner abstract class
│   ├── bola.py / idor_active.py ← BOLA/IDOR with token swapping
│   ├── jwt_scan.py              ← JWT None algorithm + signature exclusion
│   ├── ssrf.py                  ← SSRF (metadata + internal + blind)
│   ├── injection_sqli.py        ← SQL + NoSQL injection
│   ├── injection_cmd.py         ← OS command injection
│   ├── mass_assignment.py       ← Mass assignment / auto-binding
│   ├── xss.py / ssti.py        ← XSS + SSTI
│   ├── cors.py / csrf.py        ← CORS misconfiguration + CSRF
│   ├── crlf.py                  ← CRLF injection
│   ├── rate_limit.py            ← Rate limiting absence
│   ├── headers.py               ← Security headers audit
│   ├── redirect.py              ← Open redirect
│   └── xxe.py                   ← XXE injection
└── services/
    ├── engine.py                 ← AttackEngine (scanner loader + executor)
    ├── orchestrator.py           ← SessionOrchestrator (heuristics + scheduling)
    ├── reporting.py              ← ReportManager (CVSS, remediation)
    ├── report_generator.py       ← HTML + PDF report generation
    └── direct_parser.py          ← Direct OAS parser (bypass static audit)
```

---

## Docker Services

| Service | Container | Port | Description |
|---------|-----------|------|-------------|
| `backend` | `apex-backend` | `8000` | FastAPI backend (auto-restarts) |
| `frontend` | `apex-frontend` | `5173` | React dev server (HMR) |
| `frontend-prod` | `apex-frontend-prod` | `80` | Nginx production build |
| `db` | `apex-db` | `3306` | MySQL 8.0 database |

**Development stack (default):**
```bash
docker compose up -d
```

**Production frontend:**
```bash
docker compose --profile prod up -d --build frontend-prod
```

---

## Security Hardening Features

| Feature | Implementation |
|---------|---------------|
| CORS Allowlist | `ALLOWED_ORIGINS` config, applied via `CORSMiddleware` |
| Rate Limiting | `slowapi` — 2-10 req/min on scan endpoints |
| Upload Validation | Extension whitelist (`.json`, `.yaml`, `.yml`), 10MB size limit |
| Request Validation | Pydantic models + HttpUrl type enforcement |
| Structured Logging | JSON-formatted logs with session/scanner context |
| DB Health Check | MySQL `mysqladmin ping` with retry logic |
| Backend Restart Policy | `restart: always` to survive DB startup race conditions |

---

## Known Limitations

- **Auth model:** No user accounts for the APEX dashboard itself (scans are unauthenticated API calls)
- **Rate limiter storage:** In-memory; resets on restart. For production, use Redis
- **Real-time updates:** Scan progress polling (no WebSocket/SSE)
- **BOLA Token Swap:** Testing uses a hardcoded fallback ID (`35`). For best results, run against an API where the users own resources with predictable IDs

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.10, FastAPI, SQLAlchemy, Pydantic v2 |
| HTTP Client | `httpx` (sync, used inside scanner threads) |
| Database | MySQL 8.0, Alembic migrations |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, shadcn/ui |
| Containerization | Docker, Docker Compose |
| Rate Limiting | slowapi |
| Reports | Jinja2 (HTML), WeasyPrint (PDF) |

---

## Contributing / Development Notes

- All scanners must extend `BaseScanner` from `app/scanners/base.py`
- The `AttackEngine` auto-discovers and loads all scanners in `app/scanners/` at startup
- Payloads live in `app/scanner_utils/payloads.py` (single source of truth)
- Detection patterns live in `app/scanner_utils/detection.py`
- Backend hot-reloads via volume mount — no rebuild needed for Python changes

---

*APEX — Built as a Final Year Project for comprehensive API security research.*
