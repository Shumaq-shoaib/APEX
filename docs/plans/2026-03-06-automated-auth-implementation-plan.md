# Automated Authentication Implementation Plan

> **For Antigravity:** REQUIRED WORKFLOW: Use `.agent/workflows/execute-plan.md` to execute this plan in single-flow mode.

**Goal:** Implement automated authentication (Smart Guesser with Override) to replace manual Bearer token entry in APEX, making dynamic scanning of targets like VAmPI truly one-click.

**Architecture:** We will create an `AuthEngine` that can heuristically discover login endpoints from the OpenAPI Blueprint, execute login requests with user-provided credentials, and extract the resulting JWT. The `SessionOrchestrator` will use this engine to populate the session tokens *before* kicking off the attack scanners. The database schema and API routes will be updated to accept credentials instead of raw tokens.

**Tech Stack:** Python 3.10, FastAPI, SQLAlchemy, httpx

---

### Task 1: Update Database Schema

**Files:**
- Modify: `c:\Users\iamsh\Downloads\FYP\APEX-main\apex-dynamic-service\app\models\dynamic.py`
- Create: DB Migration Script

**Step 1: Update `DynamicTestSession` Model**
Modify `app/models/dynamic.py` to add new columns to `DynamicTestSession`:
```python
    # Replaces raw tokens with credentials
    auth_username = Column(String(255), nullable=True)
    auth_password = Column(String(255), nullable=True)
    auth_sec_username = Column(String(255), nullable=True)
    auth_sec_password = Column(String(255), nullable=True)
    
    # Advanced Overrides
    auth_login_endpoint = Column(String(255), nullable=True)
    auth_username_field = Column(String(100), nullable=True, default="username")
    auth_token_path = Column(String(255), nullable=True)
```
Keep `auth_token` and `auth_token_secondary` as they will be used to store the *result* of the automated login.

**Step 2: Generate Alembic Migration**
Run: `cd c:\Users\iamsh\Downloads\FYP\APEX-main\apex-dynamic-service && alembic revision --autogenerate -m "Add automated auth columns"`

**Step 3: Apply Migration**
Run: `alembic upgrade head`

---

### Task 2: Build the `AuthEngine` Service

**Files:**
- Create: `c:\Users\iamsh\Downloads\FYP\APEX-main\apex-dynamic-service\app\services\auth_engine.py`

**Step 1: Implement the `AuthEngine` Class**
Create the file with the following structure:
```python
import httpx
import json

class AuthEngine:
    def __init__(self, target_url: str, blueprint: dict):
        self.target_url = target_url.rstrip('/')
        self.blueprint = blueprint
        
    def _find_login_endpoint(self) -> str:
        # Heuristic: search blueprint paths for 'login', 'auth', 'signin'
        pass

    def _extract_token(self, response_data: dict, custom_path: str = None) -> str:
        # Heuristic: look for 'token', 'access_token', or nested keys
        pass

    def fetch_token(self, username, password, login_endpoint=None, username_field="username", token_path=None) -> str:
        # 1. Discover endpoint if not provided
        # 2. Build payload (respecting username_field)
        # 3. Post to target
        # 4. Extract and return token (or raise Error)
        pass
```

**Step 2: Add Logic for Heuristics**
Implement the internal helpers to detect common patterns (like VAmPI's `/users/v1/login` returning `{"access_token": "..."}`).

---

### Task 3: Update FastAPI Routes

**Files:**
- Modify: `c:\Users\iamsh\Downloads\FYP\APEX-main\apex-dynamic-service\app\api\routes\sessions.py`

**Step 1: Update Pydantic Schemas**
Update `SessionCreate`, `create_direct_session` form fields, and `QuickScanCreate` to accept the new credentials and override fields, removing the requirement for `auth_token`.

**Step 2: Pass new parameters to Orchestrator**
Update the API handlers to pass `auth_username`, `auth_password`, etc., into `orch.create_session()`.

---

### Task 4: Integrate `AuthEngine` into `SessionOrchestrator`

**Files:**
- Modify: `c:\Users\iamsh\Downloads\FYP\APEX-main\apex-dynamic-service\app\services\orchestrator.py`

**Step 1: Update `create_session` signature**
Modify it to accept the new auth parameters and save them to the `DynamicTestSession` object in the database.

**Step 2: Hook into `run_scan_background`**
Right after setting the session status to `RUNNING`, instantiate the `AuthEngine` (passing in the parsed static spec blueprint). Call `fetch_token()` for the primary and secondary users. Save the resulting tokens back to `session.auth_token` and `session.auth_token_secondary` so the existing attack engine naturally picks them up.

---

### Task 5: Frontend Dashboard UI Updates (API Configuration)

**Files:**
- Modify: `c:\Users\iamsh\Downloads\FYP\APEX-main\frontend\dashboard\src\pages\StaticAnalysisPage.tsx` (or wherever the trigger modal is)
- Modify: `c:\Users\iamsh\Downloads\FYP\APEX-main\frontend\dashboard\src\pages\DynamicAnalysisPage.tsx`
- Modify: `c:\Users\iamsh\Downloads\FYP\APEX-main\frontend\dashboard\src\types\api.ts`

**Step 1: Update Types**
Update TypeScript interfaces `SessionCreate` to mirror the backend changes.

**Step 2: Update UI Forms**
Replace the "Bearer Token" input boxes with "Username" and "Password" inputs.
Add a secondary user section for BOLA testing.
Add an "Advanced Settings" collapsible area for the override fields (`Login Endpoint`, `Username Field`, `Token Path`).

**Step 3: Update API Calls**
Ensure the payload sent to `/api/sessions/` and `/api/sessions/direct` matches the new schema.
