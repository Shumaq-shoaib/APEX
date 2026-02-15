# ZAP-Python Porting Walkthrough

## 1. Goal
Port the core scanning logic of OWASP ZAP (from `zaproxy-main` and `zap-extensions`) into a lightweight, standalone Python CLI, and verify it against the OWASP crAPI target.

## 2. Implementation
We created a modular Python application with the following components:

### Core Engine
- **`core/engine.py`**: Manages the request lifecycle.
    - **Concurrency**: Upscaled to **50 threads** for high-speed scanning.
    - **Authentication**: Supports Bearer Token injection.
    - **Reporting**: Generates JSON and Markdown reports.
- **`core/parser.py`**: Parses OpenAPI (v3) specs to discover endpoints, parameters (query/path), and JSON schemas.

### Scanners (Ported from Java)
| Scanner | Source (Java) | Python Implementation | Logic |
| :--- | :--- | :--- | :--- |
| **API-SEC-HEADERS** | `ContentSecurityPolicyMissingScanRule.java` | `scanners/api_headers.py` | Checks for missing CSP, HSTS, X-Content-Type. |
| **API-SQLI/NOSQLI** | `SqlInjectionScanRule.java` | `scanners/api_injection.py` | **SQLi**: Error-Based (`'`) + Time-Based (`SLEEP(5)`).<br>**NoSQLi**: MongoDB Payloads (`$ne`, `$gt`).<br>**JSON Injection**: Recursively fuzzes JSON bodies (POST/PUT). |
| **API-IDOR** | `UsernameIdorScanRule.java` | `scanners/api_idor.py` | Passive check. Hashes a list of usernames (admin, root) and scans response bodies for leaked hashes. |

## 3. Verification (crAPI)

### Target Deployment
Deployed OWASP crAPI locally on Docker:
- **Base URL**: `http://localhost:8888`
- **Spec**: Provided `crapi-openapi-spec.json`

### Authenticated Scan
We implemented `get_token.py` to acquire a valid JWT by registering/logging in a test user.

**Command:**
```bash
python main.py scan --target http://localhost:8888 --spec "..." --token "eyJ..."
```

### Results
- **Speed**: Scanned 44 endpoints in **~95 seconds** (50 threads).
- **Findings**:
    - **Total**: ~2145
    - **Security Headers**: High volume (Expected for crAPI).
    - **Injection/IDOR**: Standard payloads did not bypass crAPI's validation layers in this run.

## 4. Evidence
**Report Snippet (`report.md`)**:
```markdown
# ZAP-Python Security Report
**Target:** http://localhost:8888
**Total Findings:** 2145

## Summary
| Severity | Vulnerability | Count |
| Low | Missing Content-Security-Policy Header | 1002 |
| Low | Missing Strict-Transport-Security Header | 1002 |
```
