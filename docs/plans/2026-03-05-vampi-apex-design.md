# VAmPI Deployment and APEX Manual Testing Implementation Plan

> **For Antigravity:** REQUIRED WORKFLOW: Use `.agent/workflows/execute-plan.md` to execute this plan in single-flow mode.

**Goal:** Orchestrate the local deployment of VAmPI using its existing Docker Compose structure and verify its accessibility from within the APEX backend to enable manual security scans.

**Architecture:** VAmPI will be spun up in its own Docker Compose network on the host machine. The APEX backend container will route traffic to VAmPI using the `host.docker.internal` DNS name, which resolves to the host machine's localhost where VAmPI's ports are bound.

**Tech Stack:** Docker, Docker Compose, HTTP (curl)

---

### Task 1: Start VAmPI Containers

**Files:**
- Run: `c:\Users\iamsh\Downloads\FYP\VAmPI\docker-compose.yaml`

**Step 1: Spin up VAmPI using Docker Compose**
Run: `docker-compose up -d --build` (Make sure to be in the `c:\Users\iamsh\Downloads\FYP\VAmPI` directory).

**Step 2: Verify containers are running locally**
Run: `docker ps | grep vampi` or equivalent PowerShell command to ensure `vampi-secure` (port 5001) and `vampi-vulnerable` (port 5002) are healthy and active.

**Step 3: Initialize the VAmPI database**
Run: `curl -v http://localhost:5002/createdb`
Expected: HTTP 200 response indicating the database was populated.

---

### Task 2: Verify APEX to VAmPI Connectivity

**Files:**
- N/A (Docker container interaction)

**Step 1: Test connectivity from inside APEX backend container**
Run: `docker exec -it apex-backend curl -v http://host.docker.internal:5002/`
Expected: An HTTP 200 response with VAmPI data, confirming the APEX engine can successfully reach the VAmPI vulnerable instance via host routing.

---

### Task 3: Prepare Test Assets for Manual Execution

**Files:**
- Copy: `c:\Users\iamsh\Downloads\FYP\VAmPI\openapi_specs\openapi3.yml`

**Step 1: Locate the VAmPI OpenAPI specification**
Confirm the presence and path of `openapi3.yml` in the VAmPI repository so it can be uploaded via the APEX dashboard.

**Step 2: Note the required URLs for manual dashboard entry**
- Target URL: `http://host.docker.internal:5002`

**Step 3: (Manual) User Action Required**
The user will manually:
1. Upload the `openapi3.yml` spec to the APEX Dashboard.
2. Register/Login manually via Postman or Swagger UI (`http://localhost:5002/ui/`) to obtain a Bearer JWT.
3. Initiate the Dynamic Scan using the Target URL and the acquired token.
