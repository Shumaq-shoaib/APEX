# APEX Automated Authentication Design

## Overview
Replaces the manual "Bearer Token" copy-paste workflow with an automated smart login system. The user provides a username and password, and APEX automatically discovers the login endpoint, executes the authentication request, extracts the token, and injects it into the dynamic scan session.

## Architecture

### 1. The `AuthEngine` (New Component)
We will introduce `app/services/auth_engine.py` to handle all token fetching logic before the scan starts.
**Responsibilities:**
- Parse the API Blueprint/Spec to logically guess the login endpoint (e.g., matching paths like `/users/login`, `/auth`, `/signin` or tags).
- Execute a login request with the provided credentials.
- Heuristically extract the token from the response (looking for JSON keys like `token`, `access_token`, or `Authorization` headers).
- Fallback to exact manual overrides if heuristic guessing fails or is disabled.

### 2. Backend API Changes (`app/api/routes/sessions.py`)
Modify `SessionCreate`, `create_direct_session`, and `create_quick_session` payloads to accept:
- **Primary Auth**: `auth_username`, `auth_password`
- **Secondary Auth (BOLA)**: `auth_sec_username`, `auth_sec_password`
- **Advanced Overrides (Optional)**: `auth_login_endpoint`, `auth_username_field` (e.g., "email"), `auth_token_path` (e.g., "data.token").

The endpoint handlers will save these to the `DynamicTestSession` model, which will be updated with these new columns (replacing or supplementing the hardcoded `auth_token` strings).

### 3. Orchestrator Integration (`app/services/orchestrator.py`)
At the start of the orchestration phase (when `status` turns to `RUNNING`), before it runs the `DiscoveryEngine` or `AttackEngine`, it will:
1. Instantiate `AuthEngine`.
2. Fetch the primary token using the credentials.
3. Fetch the secondary token using the secondary credentials (if provided).
4. Save the resulting raw tokens into `session.auth_token` and `session.auth_token_secondary`.
*This ensures the 17 underlying scanners require ZERO changes. They still receive exactly what they expect: raw token strings.*

### 4. Frontend Dashboard Updates
- Modify the **Static Analysis => Start Dynamic Scan** modal and the **Dynamic Analysis** direct configuration page.
- Remove the massive text areas for pasting tokens.
- Add simple input fields for Username and Password.
- Add an expandable "Advanced Auth Settings" accordion that allows overriding the Target Login Endpoint, Username Payload Field (e.g., `email`), and Response Token Path (e.g., `body.data.jwt`).

## Execution Flow inside APEX
1. User clicks "Start Scan" with user/pass on frontend.
2. `POST /api/sessions/` -> DB records session as `PENDING` with auth configuration.
3. Background task starts -> `Orchestrator` runs.
4. `AuthEngine` kicks in, parses Blueprint, finds `/users/v1/login`.
5. `AuthEngine` sends `POST /users/v1/login {"username": "...", "password": "..."}`.
6. `AuthEngine` extracts `{"access_token": "eyJ..."}`.
7. Token is locked into the session state.
8. Dynamic Scanning resumes normally using the extracted tokens.
