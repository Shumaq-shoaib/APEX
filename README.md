# APEX: Advanced API Security Scanner

APEX is a comprehensive API security scanning platform that combines **Static Application Security Testing (SAST)** of OpenAPI specifications with **Dynamic Application Security Testing (DAST)** to identify and verify vulnerabilities in real-time.

Built with a focus on modern application security, APEX automates the detection of critical risks like **Broken Authentication**, **BOLA (Broken Object Level Authorization)**, and data exposure.

---

## 🚀 Technical Overview

### Core Features
-   **Static Analysis (SAST)**: Analyzes OpenAPI/Swagger specifications (`.json`, `.yaml`) to identify design-time security flaws (e.g., weak authentication schemas, mass assignment risks).
-   **Dynamic Verification (DAST)**: Automatically generates and executes attack probes against running APIs to verify static findings.
-   **Authenticated Scanning**: Supports `Bearer` token injection to test protected endpoints and simulate authenticated attacks (e.g., BOLA).
-   **Interactive Dashboard**: A modern React-based UI for managing scans, visualizing results, and inspecting detailed execution logs.
-   **Dockerized Architecture**: Fully containerized setup for easy deployment and isolation.

### Architecture
The system consists of three main components:
1.  **Backend (`apex-backend`)**: 
    -   **Tech**: Python (FastAPI), SQLAlchemy (MySQL), Docker SDK.
    -   **Role**: Orchestrates scans, runs the `AttackEngine`, manages the database, and exposes REST APIs.
    -   **Networking**: Runs in `host` network mode to seamlessly access local target APIs (like crAPI running on `localhost`).
2.  **Frontend (`apex-frontend`)**:
    -   **Tech**: React, Vite, TailwindCSS, Shadcn UI.
    -   **Role**: User interface for uploading specs, starting scans, and viewing live results.
3.  **Database (`apex-db`)**:
    -   **Tech**: MySQL 8.0.
    -   **Role**: Persists scan sessions, findings, evidence logs, and rules.

---

## 📂 Project Structure

```text
APEX-code/
├── apex-dynamic-service/       # Python Backend (DAST Engine)
│   ├── app/
│   │   ├── api/                # REST API Routes
│   │   ├── models/             # Database Models
│   │   ├── services/           # Core Logic (Engine, Checks, Orchestrator)
│   │   └── schemas/            # Pydantic Schemas
│   └── Dockerfile
├── frontend/                   # React Frontend
│   ├── dashboard/              # Dashboard Source Code
│   └── Dockerfile
├── static_analysis/            # SAST Engine (Shared Module)
│   └── src/                    # Analysis Rules & Logic
├── deploy/                     # Deployment Scripts
│   └── crapi/                  # crAPI (Target) Deployment Configuration
├── docker-compose.yml          # Main APEX Deployment Definition
└── scripts/                    # Utility Scripts
```

---

## 🛠️ How to Run

### Prerequisites
-   **Docker** & **Docker Compose** installed on your Linux machine.
-   **Target API**: Access to an API to scan (we use OWASP crAPI for demonstration).

### 1. Deploy the Target (OWASP crAPI)
First, start the vulnerable application you want to test. We have included a deployment configuration for crAPI.

```bash
cd deploy/crapi
./start.sh
```
*Wait for crAPI to start. Verify it is accessible at [http://localhost:8888](http://localhost:8888).*

### 2. Start APEX Scanner
Run the scanner stack using Docker Compose from the root directory.

```bash
# From APEX-code root
docker compose up -d --build
```

### 3. Access the Dashboard
Open your browser and navigate to:
**[http://localhost:5173](http://localhost:5173)**

---

## 🧪 Usage Guide

### Running a Scan
1.  **Upload Spec**: On the Dashboard, verify that `crapi-openapi-spec.json` is detected (pre-loaded).
2.  **Start Scan**: Click "Start Dynamic Scan" on the latest analysis card.
3.  **Configure Target**: 
    -   **Target URL**: Defaults to `http://localhost:8888` (detected from spec).
    -   **Auth Token (Optional)**: Login to crAPI, copy the **Bearer Token**, and paste it here to enable authenticated BOLA testing.
4.  **Monitor Results**: Watch the "Execution Queue" and "Terminal Output" in real-time.
5.  **Inspect Findings**: Click on any "Verified Vulnerability" card to see the exact HTTP request/response logs that proved the vulnerability.

---

## ⚙️ Configuration Notes

-   **Networking**: The backend uses `network_mode: "host"`. This allows it to reach services running on your machine's `localhost` directly.
-   **Database**: The MySQL database is exposed on port `3306`. Connection string: `mysql+mysqlconnector://apex:apex@127.0.0.1:3306/apex_db`.

## 📦 Containerization Status

✅ **Fully Containerized**: 
-   The entire APEX tool (Backend, Frontend, DB) is defined in `docker-compose.yml`.
-   You can run it with a single command: `docker compose up`.
-   *Note*: The Target (crAPI) is managed separately to simulate a real-world "black box" environment where the scanner and target are distinct systems.
