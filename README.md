# APEX: Advanced API Security Scanner

APEX is a full-stack API security platform that combines:
- Static Application Security Testing (SAST) against OpenAPI specs
- Dynamic Application Security Testing (DAST) against live endpoints

It provides a FastAPI backend, a React dashboard, and a Python CLI scanner.

---

## Current Status (Through Phase 4)

The project has completed major hardening and frontend stabilization work.

Implemented and verified:
- Backend Phase 1 and Phase 2 hardening (CORS allowlist, upload validation, rate limiting, structured logging, improved `/health`, stricter request validation)
- Frontend hardening:
  - centralized API base URL configuration
  - environment validation support
  - improved type coverage in core dashboard flows
  - removed duplicate dashboard components to reduce drift
  - error boundary integration
  - Vitest test setup with baseline component tests
- Production frontend container path:
  - multi-stage build in `frontend/dashboard/Dockerfile.prod`
  - Nginx SPA routing fallback in `frontend/dashboard/nginx.conf`
  - compose profile `prod` with `frontend-prod` service

Known verified commands (latest checks):
- `npm run test -- --run` (frontend) passes
- `npm run build` (frontend) passes
- `docker build -f frontend/dashboard/Dockerfile.prod -t apex-frontend-prod frontend/dashboard` passes
- `docker compose --profile prod up -d --build frontend-prod` starts frontend-prod/backend/db

---

## Architecture

APEX consists of four major runtime parts:

1. Backend service: `apex-dynamic-service`
   - FastAPI + SQLAlchemy
   - REST APIs for specs and sessions
   - scan orchestration and persistence

2. Frontend dashboard: `frontend/dashboard`
   - React + TypeScript + Vite + Tailwind + shadcn
   - static and dynamic scan workflows
   - history and findings visualization

3. Static analysis engine: `static_analysis`
   - OpenAPI rule evaluation and blueprint generation

4. Dynamic scanner engine + CLI: `ZAP-python`
   - attack modules and CLI execution path

Database:
- MySQL (compose service `db`) for persisted specs, sessions, test cases, findings, and evidence.

---

## Project Structure

```text
APEX-main/
├── apex-dynamic-service/        # FastAPI backend
│   ├── app/
│   │   ├── api/routes/          # specs + sessions endpoints
│   │   ├── core/                # config, limiter, logging
│   │   ├── db/                  # SQLAlchemy session/base
│   │   ├── models/              # dynamic and static entities
│   │   └── services/            # orchestrator, engine wrappers
│   └── alembic/                 # migrations
├── frontend/dashboard/          # React frontend
│   ├── src/
│   │   ├── components/dashboard/# primary dashboard components
│   │   ├── components/layout/   # sidebar/layout shell
│   │   ├── components/ui/       # shadcn ui primitives
│   │   ├── lib/                 # config, env, helpers
│   │   ├── pages/               # routed pages
│   │   └── types/               # shared frontend types
│   ├── Dockerfile               # dev container
│   ├── Dockerfile.prod          # production multi-stage image
│   └── vitest.config.ts         # frontend tests
├── static_analysis/             # SAST module
├── ZAP-python/                  # CLI + dynamic scanner logic
├── deploy/crapi/                # optional vulnerable target setup
├── docs/                        # analysis and planning docs
├── tests/                       # backend/system verification scripts
├── docker-compose.yml
└── requirements.txt
```

---

## Features

### Security and API Hardening
- CORS allowlist via config (`ALLOWED_ORIGINS`)
- Rate limiting (slowapi) on high-cost endpoints
- Upload validation for OpenAPI files (extension + size constraints)
- Request validation with Pydantic models (including URL validation)
- Structured logging with session-aware events
- Health endpoint with component status (`database`, `scanner`)

### Scanning Workflows
- Static analysis upload -> analysis -> persisted report and blueprint
- Dynamic scan session orchestration and background execution
- Session polling and findings retrieval
- Auth token support in dynamic scanning paths

### Frontend Dashboard
- Static analysis page with scan summary and findings
- Dynamic analysis console for live scan execution
- History page with previous scan retrieval
- Error boundary fallback UI
- Test baseline (Vitest + Testing Library)

### Deployment
- Development stack with Docker Compose
- Production frontend image with Nginx and SPA fallback
- Profile-based compose startup for production frontend

---

## Quick Start

### Prerequisites
- Docker + Docker Compose
- Node.js (for local frontend dev/testing)
- Python (for backend/CLI local workflows)

### 1) Optional: Start target app (crAPI demo)

```bash
cd deploy/crapi
./start.sh
```

Expected target URL: `http://localhost:8888`

### 2) Start APEX full stack (dev profile)

```bash
docker compose up -d --build
```

Access:
- Frontend dev dashboard: `http://localhost:5173`
- Backend API/docs: `http://localhost:8000/docs`

### 3) Frontend tests/build (local)

```bash
cd frontend/dashboard
npm run test -- --run
npm run build
```

### 4) Production frontend profile

```bash
docker compose --profile prod up -d --build frontend-prod
```

Expected frontend URL: `http://localhost`

---

## CLI Usage (ZAP-python)

```bash
pip install -r requirements.txt
python ZAP-python/main.py scan --target http://localhost:8888 --spec path/to/openapi.json
python ZAP-python/main.py --help
```

---

## Limitations and Known Gaps

### Security and Access Control
- No full user authentication/authorization model for dashboard/backend routes yet
- Default compose credentials are development-oriented and should be replaced in real deployments

### Rate Limiting and Scalability
- Current limiter storage is in-memory; limits reset on service restart
- For distributed/production deployments, Redis-backed limiter storage is recommended

### Frontend and UX
- Routes `/rules` and `/settings` are still placeholders
- Real-time dynamic updates currently rely on polling (not WebSocket/SSE)

### Testing and Quality
- Frontend test coverage is still minimal (baseline tests only)
- No comprehensive E2E test suite yet

### Build and Runtime Compatibility
- Python dependency pinning in `requirements.txt` is tuned for project stack; some host Python versions (notably newer 3.13 environments) may require a controlled venv/container workflow

---

## Verification Checklist

Use this quick checklist after changes:

```bash
# frontend checks
cd frontend/dashboard
npm run test -- --run
npm run build

# hardcoded URL regression check (expect no results)
# use rg in repo root:
# rg "127\.0\.0\.1:8000" frontend/dashboard/src

# production frontend image
cd ../..
docker build -f frontend/dashboard/Dockerfile.prod -t apex-frontend-prod frontend/dashboard
docker compose --profile prod up -d --build frontend-prod
```

---

## Notes

- This README reflects the current state after the Phase 4 frontend hardening and cleanup work.
- For deeper technical details, see documents under `docs/`.
