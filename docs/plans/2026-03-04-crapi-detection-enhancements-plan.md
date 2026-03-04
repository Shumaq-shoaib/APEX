# crAPI Detection Enhancements Implementation Plan

> **For Antigravity:** REQUIRED WORKFLOW: Use `.agent/workflows/execute-plan.md` to execute this plan in single-flow mode.

**Goal:** Improve APEX's detection logic to eliminate SSRF false positives, expand mass assignment parameters, and introduce automated token swapping for mathematically rigorous IDOR/BOLA discovery.

**Architecture:** We will modify the `SsrfScanner` to demand content reflection rather than just status codes. We will expand payloads in `MassAssignmentScanner` and `PayloadLibrary`. Finally, we will refactor `ActiveIdorScanner` and the engine's `ScannerContext` to utilize `auth_token_secondary` to authenticate as a secondary victim user and prove cross-user data access.

**Tech Stack:** Python 3.10, FastAPI, SQLAlchemy

---

### Task 1: Tune SSRF Detection Logic

**Files:**
- Modify: `c:\Users\iamsh\Downloads\FYP\APEX-main\apex-dynamic-service\app\scanners\ssrf.py`

**Step 1: Write the minimal implementation**
- Update the `_analyze_response` method.
- Remove the block that flags Critical SSRF simply because `res.status_code == 200` for `:8888`.
- Instead, require that the response text matches a known target page signature (e.g., `<title>crAPI</title>` or `response_from_mechanic_api`). If it's a Blind SSRF it should rely strictly on timeouts or specific error signatures.

**Step 2: Commit**
```bash
git add apex-dynamic-service/app/scanners/ssrf.py
git commit -m "fix(scanner): eliminate SSRF false positives on 200 OK responses"
```

---

### Task 2: Expand Mass Assignment & NoSQLi Payloads

**Files:**
- Modify: `c:\Users\iamsh\Downloads\FYP\APEX-main\apex-dynamic-service\app\scanners\mass_assignment.py`
- Modify: `c:\Users\iamsh\Downloads\FYP\APEX-main\apex-dynamic-service\app\scanner_utils\payloads.py`

**Step 1: Write the minimal implementation**
- In `mass_assignment.py`, expand `SENSITIVE_PARAMS` to include crAPI-specific keys: `"credit": 1000000`, `"available_credit": 1000000`, `"mechanic_code": "TRAC_MECH1"`, `"mechanic_api": "http://localhost:8888"`.
- In `payloads.py`, ensure NoSQL Injection bypass payloads are comprehensive (e.g., `{"$ne": null}`, `{"$gt": ""}`) in the SQLI/Injection lists.

**Step 2: Commit**
```bash
git add apex-dynamic-service/app/scanners/mass_assignment.py apex-dynamic-service/app/scanner_utils/payloads.py
git commit -m "feat(payloads): add crAPI-targeted mass assignment and NoSQLi payloads"
```

---

### Task 3: Context & Engine Setup for Secondary Tokens

**Files:**
- Modify: `c:\Users\iamsh\Downloads\FYP\APEX-main\apex-dynamic-service\app\scanner_core\context.py`
- Modify: `c:\Users\iamsh\Downloads\FYP\APEX-main\apex-dynamic-service\app\services\engine.py`

**Step 1: Write the minimal implementation**
- In `context.py`, add `auth_token_secondary: str = None` to the `ScannerContext` dataclass.
- Add a method `get_secondary_headers()` that returns headers using `auth_token_secondary` instead of the primary token.
- In `engine.py`, when creating the `ScannerContext` inside `run_dynamic_scan` (or similar), pass `session.auth_token_secondary` from the database record into the context.

**Step 2: Commit**
```bash
git add apex-dynamic-service/app/scanner_core/context.py apex-dynamic-service/app/services/engine.py
git commit -m "feat(engine): plumb secondary auth token into scanner context"
```

---

### Task 4: Implement Automated Token Swapping in IDOR/BOLA

**Files:**
- Modify: `c:\Users\iamsh\Downloads\FYP\APEX-main\apex-dynamic-service\app\scanners\idor_active.py`

**Step 1: Write the minimal implementation**
- In `ActiveIdorScanner.run()`, add a new test phase for Token Swapping:
  1. Check if `self.context.auth_token_secondary` is present.
  2. If the endpoint requires an ID (path params), fetch it using the primary token `get_headers()` and the primary user's ID.
  3. Fetch the exact same URL but using `get_secondary_headers()`. 
  4. If the secondary user gets a 200/20x response and the response body matches the primary user's sensitive data, flag it as a Critical BOLA vulnerability.

**Step 2: Commit**
```bash
git add apex-dynamic-service/app/scanners/idor_active.py
git commit -m "feat(scanner): implement automated token swapping for rigorous IDOR detection"
```

---

### Task 5: Verify the Scanners

**Files:**
- Execute a new scan via Dashboard or API using both User 1 and User 2 JWT tokens.

**Step 1: Run the verification**
- Restart the backend container so new code is loaded.
- Ensure crAPI is targeted and the dynamic scan initializes.
- Watch logs / database to verify that SSRF false positives are gone and new IDOR/Mass Assignment vulnerabilities are caught.
