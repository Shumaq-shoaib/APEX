# Unified APEX Scanner Engine — Implementation Plan

> **For Antigravity:** REQUIRED WORKFLOW: Use `.agent/workflows/execute-plan.md` to execute this plan in single-flow mode.

**Goal:** Consolidate ZAP-python + Astra modules into a single native APEX scanning engine with 17 scanners, unified branding, and zero external dependencies.

**Architecture:** Move all scanner code from `ZAP-python/` into `apex-dynamic-service/app/scanners/`, port 7 Astra modules as new `BaseScanner` subclasses, merge duplicated security-headers logic, rebrand all IDs from `API-*` to `APEX-*`, and update engine/orchestrator/reporting to support new check types.

**Tech Stack:** Python 3.10, FastAPI, SQLAlchemy, httpx, pydantic

---

## Phase 1: Foundation — Move Packages Inline

### Task 1: Create scanner_core package

**Files:**
- Create: `apex-dynamic-service/app/scanner_core/__init__.py`
- Create: `apex-dynamic-service/app/scanner_core/context.py`

**Steps:**
1. Create `app/scanner_core/__init__.py` (empty)
2. Copy `ZAP-python/core/context.py` → `app/scanner_core/context.py`. Update docstring: remove "ZAP" references, rename to "APEX Scan Context". No logic changes.
3. Commit: `git commit -m "feat: create scanner_core package (moved from ZAP-python)"`

---

### Task 2: Create scanner_utils package

**Files:**
- Create: `apex-dynamic-service/app/scanner_utils/__init__.py`
- Create: `apex-dynamic-service/app/scanner_utils/http.py`
- Create: `apex-dynamic-service/app/scanner_utils/detection.py`
- Create: `apex-dynamic-service/app/scanner_utils/payloads.py`

**Steps:**
1. Create `app/scanner_utils/__init__.py` (empty)
2. Copy `ZAP-python/utils/http_utils.py` → `app/scanner_utils/http.py` — no logic changes
3. Copy `ZAP-python/utils/detection.py` → `app/scanner_utils/detection.py` — no logic changes
4. Copy `ZAP-python/utils/payloads.py` → `app/scanner_utils/payloads.py` — no logic changes yet (payloads expanded in Phase 3)
5. Commit: `git commit -m "feat: create scanner_utils package (moved from ZAP-python)"`

---

### Task 3: Move existing scanners into app/scanners

**Files:**
- Create: `apex-dynamic-service/app/scanners/__init__.py`
- Create: `apex-dynamic-service/app/scanners/base.py`
- Create: `apex-dynamic-service/app/scanners/idor_active.py`
- Create: `apex-dynamic-service/app/scanners/idor_passive.py`
- Create: `apex-dynamic-service/app/scanners/injection_sqli.py`
- Create: `apex-dynamic-service/app/scanners/injection_cmd.py`
- Create: `apex-dynamic-service/app/scanners/jwt_scan.py`
- Create: `apex-dynamic-service/app/scanners/mass_assignment.py`
- Create: `apex-dynamic-service/app/scanners/redirect.py`
- Create: `apex-dynamic-service/app/scanners/ssrf.py`
- Create: `apex-dynamic-service/app/scanners/xxe.py`

**Steps:**
1. Create `app/scanners/__init__.py` (empty)
2. Copy `ZAP-python/scanners/base.py` → `app/scanners/base.py`. Update imports: `from scanners.base` → internal relative imports.
3. For each of the 9 scanner files below, copy from ZAP-python, then apply these changes:
   - Update imports: `from scanners.base import BaseScanner` → `from app.scanners.base import BaseScanner`
   - Update imports: `from utils.http_utils import HttpUtils` → `from app.scanner_utils.http import HttpUtils`
   - Update imports: `from utils.payloads import PayloadLibrary` → `from app.scanner_utils.payloads import PayloadLibrary`
   - Update imports: `from utils.detection import DetectionUtils` → `from app.scanner_utils.detection import DetectionUtils`
   - Rename `scan_id` property return value: `API-*` → `APEX-*`
   - Remove any `sys.path` manipulation lines

   | Source (ZAP-python) | Target (app/scanners) | Old scan_id | New scan_id |
   |---|---|---|---|
   | `api_active_idor.py` | `idor_active.py` | `API-ACTIVE-IDOR` | `APEX-IDOR-ACTIVE` |
   | `api_idor.py` | `idor_passive.py` | `API-IDOR-PASSIVE` | `APEX-IDOR-PASSIVE` |
   | `api_injection.py` | `injection_sqli.py` | `API-SQLI` | `APEX-SQLI` |
   | `api_command_injection.py` | `injection_cmd.py` | `API-CMD-INJ` | `APEX-CMD-INJ` |
   | `api_jwt.py` | `jwt_scan.py` | `API-JWT-SCAN` | `APEX-JWT` |
   | `api_mass_assignment.py` | `mass_assignment.py` | `API-MASS-ASSIGN` | `APEX-MASS-ASSIGN` |
   | `api_redirect.py` | `redirect.py` | `API-REDIRECT` | `APEX-REDIRECT` |
   | `api_ssrf.py` | `ssrf.py` | `API-SSRF` | `APEX-SSRF` |
   | `api_xxe.py` | `xxe.py` | `API-XXE` | `APEX-XXE` |

4. Commit: `git commit -m "feat: move 10 scanners into app/scanners with APEX branding"`

---

### Task 4: Update engine.py — rebrand and use native imports

**Files:**
- Modify: `apex-dynamic-service/app/services/engine.py`

**Steps:**
1. Replace imports (lines 11-16):
   ```python
   # OLD
   # Import ZAP-python components (Path added in main.py)
   try:
       from core.context import ScanContext, AuthConfig
       from scanners.base import BaseScanner
   except ImportError as e:
       logging.error(f"Failed to import ZAP-python modules: {e}")
   
   # NEW
   from app.scanner_core.context import ScanContext, AuthConfig
   from app.scanners.base import BaseScanner
   ```
2. Rename `_load_zap_scanners` → `_load_scanners` (line 30). Update the call on line 26 too.
3. Update the method body: change `import scanners` → `import app.scanners as scanners_pkg`, update `package = scanners_pkg`, `prefix = scanners_pkg.__name__ + "."`, skip `"app.scanners.base"`.
4. Update log messages: remove "ZAP" from all log strings (lines 28, 57, 59, 61, 64, 79, 84, 88, 108)
5. Update `_get_scanners_for_check` mapping to use new `APEX-*` IDs and add new check types:
   ```python
   mapping = {
       CheckType.BOLA: ["APEX-IDOR-ACTIVE"],
       CheckType.BROKEN_AUTH: ["APEX-JWT", "APEX-SEC-HEADERS", "APEX-BROKEN-AUTH"],
       CheckType.SQLI: ["APEX-SQLI"],
       CheckType.INJECTION: ["APEX-CMD-INJ"],
       CheckType.SSRF: ["APEX-SSRF"],
       CheckType.DATA_EXPOSURE: ["APEX-IDOR-PASSIVE", "APEX-MASS-ASSIGN"],
       CheckType.XSS: ["APEX-XSS"],
       CheckType.OTHER: ["APEX-REDIRECT", "APEX-XXE"],
       CheckType.CORS: ["APEX-CORS"],
       CheckType.CSRF: ["APEX-CSRF"],
       CheckType.CRLF: ["APEX-CRLF"],
       CheckType.RATE_LIMIT: ["APEX-RATE-LIMIT"],
       CheckType.SSTI: ["APEX-SSTI"],
   }
   ```
6. Rename `_report_zap_finding` → `_report_finding`. Update default title from `'ZAP Finding'` to `'APEX Finding'`.
7. Rename variable `zap_context` → `scan_context` and `zap_finding` → `finding` throughout.
8. Commit: `git commit -m "refactor: rebrand engine.py — remove all ZAP references, use native imports"`

---

### Task 5: Update main.py — remove sys.path hack

**Files:**
- Modify: `apex-dynamic-service/app/main.py`

**Steps:**
1. Remove lines 25-29 (the ZAP-python sys.path block):
   ```python
   # REMOVE these lines:
   # Add ZAP-python to path for dynamic scanning modules
   # In Docker, ZAP-python is mounted at /ZAP-python; locally it's relative to project root
   zap_python_path = "/ZAP-python" if os.path.isdir("/ZAP-python") else os.path.join(project_root, "ZAP-python")
   if zap_python_path not in sys.path:
       sys.path.append(zap_python_path)
   ```
2. Commit: `git commit -m "refactor: remove ZAP-python sys.path hack from main.py"`

---

### Task 6: Update docker-compose.yml — remove ZAP-python volume

**Files:**
- Modify: `APEX-main/docker-compose.yml`

**Steps:**
1. Remove line 25: `- ./ZAP-python:/ZAP-python`
2. Remove the comment on line 24: `# Mount ZAP-python dynamic scanners`
3. Commit: `git commit -m "refactor: remove ZAP-python volume mount from docker-compose"`

---

### Task 7: Verify Phase 1

**Steps:**
1. Run import test:
   ```bash
   cd APEX-main/apex-dynamic-service
   python -c "from app.scanners.base import BaseScanner; from app.scanner_core.context import ScanContext; from app.scanner_utils.http import HttpUtils; print('All imports OK')"
   ```
   Expected: `All imports OK`

2. Run scanner loading test:
   ```bash
   cd APEX-main/apex-dynamic-service
   python -c "
   from app.scanner_core.context import ScanContext
   from app.scanners.base import BaseScanner
   import importlib, pkgutil, app.scanners as pkg
   from inspect import isclass
   ctx = ScanContext(target_url='http://localhost')
   count = 0
   for _, name, _ in pkgutil.iter_modules(pkg.__path__, pkg.__name__ + '.'):
       if 'base' in name: continue
       mod = importlib.import_module(name)
       for attr_name in dir(mod):
           attr = getattr(mod, attr_name)
           if isclass(attr) and issubclass(attr, BaseScanner) and attr is not BaseScanner:
               s = attr(ctx)
               assert s.scan_id.startswith('APEX-'), f'{s.scan_id} not rebranded'
               count += 1
               print(f'  OK: {s.scan_id} ({s.name})')
   print(f'Loaded {count} scanners')
   assert count == 10, f'Expected 10, got {count}'
   "
   ```
   Expected: 10 scanners listed, all with `APEX-*` IDs

3. Commit: `git commit -m "verify: Phase 1 complete — all 10 scanners load natively"`

---

## Phase 2: Data Model & Reporting Updates

### Task 8: Add new CheckType enum values

**Files:**
- Modify: `apex-dynamic-service/app/models/dynamic.py:22-30`

**Steps:**
1. Add new enum values after `OTHER = "OTHER"` (line 30):
   ```python
   class CheckType(str, enum.Enum):
       BOLA = "BOLA"
       BROKEN_AUTH = "BROKEN_AUTH"
       DATA_EXPOSURE = "DATA_EXPOSURE"
       SQLI = "SQLI"
       XSS = "XSS"
       SSRF = "SSRF"
       INJECTION = "INJECTION"
       OTHER = "OTHER"
       CORS = "CORS"
       CSRF = "CSRF"
       CRLF = "CRLF"
       RATE_LIMIT = "RATE_LIMIT"
       SSTI = "SSTI"
   ```
2. Commit: `git commit -m "feat: add CORS, CSRF, CRLF, RATE_LIMIT, SSTI to CheckType enum"`

---

### Task 9: Update ReportManager with new CVSS scores and remediation

**Files:**
- Modify: `apex-dynamic-service/app/services/reporting.py`

**Steps:**
1. Add CVSS scores for new CheckTypes (after the existing `CheckType.XSS` block around line 44):
   ```python
   if check_type == CheckType.CORS:
       if severity == Severity.HIGH: return 7.5
       return 5.3

   if check_type == CheckType.CSRF:
       if severity == Severity.HIGH: return 8.0
       return 6.5

   if check_type == CheckType.CRLF:
       if severity == Severity.HIGH: return 7.5
       return 6.1

   if check_type == CheckType.RATE_LIMIT:
       if severity == Severity.HIGH: return 7.5
       return 5.3

   if check_type == CheckType.SSTI:
       if severity == Severity.CRITICAL: return 9.8
       if severity == Severity.HIGH: return 8.6
       return 7.2
   ```
2. Add remediation advice for new CheckTypes (after the existing blocks):
   ```python
   if check_type == CheckType.CORS:
       return "1. Set Access-Control-Allow-Origin to specific trusted domains.\n2. Never reflect arbitrary Origins.\n3. Avoid Access-Control-Allow-Credentials with wildcard origins."

   if check_type == CheckType.CSRF:
       return "1. Implement anti-CSRF tokens on all state-changing endpoints.\n2. Use SameSite cookie attribute.\n3. Validate Content-Type headers."

   if check_type == CheckType.CRLF:
       return "1. Sanitize CR (\\r) and LF (\\n) characters from all user input.\n2. Use frameworks that auto-encode header values.\n3. Validate and reject input containing control characters."

   if check_type == CheckType.RATE_LIMIT:
       return "1. Implement rate limiting on authentication endpoints.\n2. Use CAPTCHA after repeated failures.\n3. Implement account lockout policies."

   if check_type == CheckType.SSTI:
       return "1. Never pass user input directly into template engines.\n2. Use sandboxed template environments.\n3. Prefer logic-less templates (Mustache) over full engines."
   ```
3. Commit: `git commit -m "feat: add CVSS scores and remediation for new check types"`

---

## Phase 3: New Astra Scanners

### Task 10: Add Astra payloads to PayloadLibrary

**Files:**
- Modify: `apex-dynamic-service/app/scanner_utils/payloads.py`

**Steps:**
1. Add these new payload lists to the `PayloadLibrary` class:
   - `XSS_PAYLOADS` — copy from `Astra/Payloads/xss.txt` (10 payloads) as a Python list
   - `CRLF_PAYLOADS` — copy from `Astra/Payloads/crlf.txt` (16 payloads) as a Python list
   - `SSTI_PAYLOADS` — create list: `["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{7*'7'}}", "{{config}}", "${class.forName('java.lang.Runtime')}"]`
   - `CORS_EVIL_ORIGINS` — create list: `["http://evil.com", "https://evil.com", "null"]`
   - `CSRF_HEADER_NAMES` — create list: `["X-CSRF-Token", "X-XSRF-Token", "X-CSRFToken", "csrf-token", "csrf_token", "_csrf"]`
   - `RATE_LIMIT_SENSITIVE_PARAMS` — create list: `["password", "pin", "otp", "cvv", "pass", "secret"]`
2. Commit: `git commit -m "feat: add XSS, CRLF, SSTI, CORS, CSRF, rate-limit payloads"`

---

### Task 11: Add detection patterns

**Files:**
- Modify: `apex-dynamic-service/app/scanner_utils/detection.py`

**Steps:**
1. Add to the `DetectionUtils` class:
   - `SSTI_RESULT_PATTERNS` — list: `[r"49", r"7777777"]`
   - `XSS_REFLECTION_PATTERNS` — list: `[r"<script>alert\(1\)</script>", r"<svg onload=", r"<img src=xss onerror=", r"alert\(1\)", r"confirm\(1\)"]`
   - `CRLF_INDICATOR` — string: `"CRLF-Test"`
   - `RATE_LIMIT_SIGNALS` — list: `["rate limit", "too many", "captcha", "Maximum login", "exceed", "throttl"]`
2. Commit: `git commit -m "feat: add SSTI, XSS, CRLF, rate-limit detection patterns"`

---

### Task 12: Create CORS scanner

**Files:**
- Create: `apex-dynamic-service/app/scanners/cors.py`

**Steps:**
1. Create `CorsScanner(BaseScanner)` with `scan_id = "APEX-CORS"`, `name = "CORS Misconfiguration Scanner"`, `category = "API7:2023 Security Misconfiguration"`.
2. Port logic from `Astra/modules/cors.py`: generate evil origins, send requests with `Origin` header, check `Access-Control-Allow-Origin` reflection and `Access-Control-Allow-Credentials`. Use `HttpUtils.send_request_recorded` and `self.add_finding`.
3. Commit: `git commit -m "feat: add APEX-CORS scanner (ported from Astra)"`

---

### Task 13: Create CSRF scanner

**Files:**
- Create: `apex-dynamic-service/app/scanners/csrf.py`

**Steps:**
1. Create `CsrfScanner(BaseScanner)` with `scan_id = "APEX-CSRF"`.
2. Port logic from `Astra/modules/csrf.py`: detect CSRF headers, test removal/tampering, test Content-Type bypass. Only on POST/PUT/DELETE. Use `HttpUtils` for all requests.
3. Commit: `git commit -m "feat: add APEX-CSRF scanner (ported from Astra)"`

---

### Task 14: Create CRLF scanner

**Files:**
- Create: `apex-dynamic-service/app/scanners/crlf.py`

**Steps:**
1. Create `CrlfScanner(BaseScanner)` with `scan_id = "APEX-CRLF"`.
2. Port logic from `Astra/modules/crlf.py`: inject 16 CRLF payloads from `PayloadLibrary.CRLF_PAYLOADS` into query params and body fields. Check response headers for `CRLF-Test` indicator.
3. Commit: `git commit -m "feat: add APEX-CRLF scanner (ported from Astra)"`

---

### Task 15: Create Rate Limit scanner

**Files:**
- Create: `apex-dynamic-service/app/scanners/rate_limit.py`

**Steps:**
1. Create `RateLimitScanner(BaseScanner)` with `scan_id = "APEX-RATE-LIMIT"`.
2. Port logic from `Astra/modules/rate_limit.py`: identify sensitive params, send 50 rapid requests, check for rate-limit rejection signals.
3. Commit: `git commit -m "feat: add APEX-RATE-LIMIT scanner (ported from Astra)"`

---

### Task 16: Create SSTI scanner

**Files:**
- Create: `apex-dynamic-service/app/scanners/ssti.py`

**Steps:**
1. Create `SstiScanner(BaseScanner)` with `scan_id = "APEX-SSTI"`.
2. Native reimplementation (NOT tplmap): inject math expressions from `PayloadLibrary.SSTI_PAYLOADS` into params/body. Check if response contains computed results (`49`, `7777777`) or engine-specific markers.
3. Commit: `git commit -m "feat: add APEX-SSTI scanner (native reimpl of Astra template_injection)"`

---

### Task 17: Create XSS scanner

**Files:**
- Create: `apex-dynamic-service/app/scanners/xss.py`

**Steps:**
1. Create `XssScanner(BaseScanner)` with `scan_id = "APEX-XSS"`.
2. Port logic from `Astra/modules/xss.py` with 4 injection vectors: query params, URI path, body fields, headers (Referer, User-Agent). Use `PayloadLibrary.XSS_PAYLOADS`. Check reflection using `DetectionUtils.XSS_REFLECTION_PATTERNS`. Assess impact via CSP/X-Content-Type-Options presence.
3. Commit: `git commit -m "feat: add APEX-XSS scanner (ported from Astra)"`

---

### Task 18: Create Broken Auth scanner

**Files:**
- Create: `apex-dynamic-service/app/scanners/broken_auth.py`

**Steps:**
1. Create `BrokenAuthScanner(BaseScanner)` with `scan_id = "APEX-BROKEN-AUTH"`.
2. Port logic from `Astra/modules/broken_auth.py`: session fixation checks (URL params), token stripping (replay without Authorization header, flag if 2xx).
3. Commit: `git commit -m "feat: add APEX-BROKEN-AUTH scanner (ported from Astra)"`

---

### Task 19: Create merged Security Headers scanner

**Files:**
- Create: `apex-dynamic-service/app/scanners/security_headers.py`

**Steps:**
1. Create `SecurityHeadersScanner(BaseScanner)` with `scan_id = "APEX-SEC-HEADERS"`.
2. Merge checks from ZAP-python `api_headers.py` (CSP, X-Content-Type-Options, HSTS) and Astra `security_headers_missing.py` (X-XSS-Protection validation, X-Frame-Options, cookie security, server version disclosure). Total: 7+ checks.
3. Commit: `git commit -m "feat: add merged APEX-SEC-HEADERS scanner (ZAP-python + Astra)"`

---

## Phase 4: Orchestrator & Integration

### Task 20: Update orchestrator heuristics

**Files:**
- Modify: `apex-dynamic-service/app/services/orchestrator.py:153-193`

**Steps:**
1. Add new heuristic rules in the endpoint loop (after the existing SQLI/SSRF/INJECTION block at line 192):
   ```python
   # Logic 4: CORS — every endpoint
   key = (path, method, CheckType.CORS)
   if key not in queued_cases:
       self.db.add(DynamicTestCase(
           session_id=session.id, endpoint_path=path, method=method,
           check_type=CheckType.CORS, status=CaseStatus.QUEUED
       ))
       queued_cases.add(key)

   # Logic 5: CSRF — POST/PUT/DELETE only
   if method in ("POST", "PUT", "DELETE"):
       key = (path, method, CheckType.CSRF)
       if key not in queued_cases:
           self.db.add(DynamicTestCase(
               session_id=session.id, endpoint_path=path, method=method,
               check_type=CheckType.CSRF, status=CaseStatus.QUEUED
           ))
           queued_cases.add(key)

   # Logic 6: XSS / CRLF / SSTI — endpoints with params
   if ep.get("params") or ep.get("schema"):
       for ct in [CheckType.XSS, CheckType.CRLF, CheckType.SSTI]:
           key = (path, method, ct)
           if key not in queued_cases:
               self.db.add(DynamicTestCase(
                   session_id=session.id, endpoint_path=path, method=method,
                   check_type=ct, status=CaseStatus.QUEUED
               ))
               queued_cases.add(key)

   # Logic 7: Rate Limit — POST/PUT with sensitive params
   if method in ("POST", "PUT") and ep.get("schema"):
       schema_props = ep.get("schema", {}).get("properties", {})
       sensitive = ["password", "pin", "otp", "cvv", "pass", "secret"]
       if any(s in k.lower() for k in schema_props for s in sensitive):
           key = (path, method, CheckType.RATE_LIMIT)
           if key not in queued_cases:
               self.db.add(DynamicTestCase(
                   session_id=session.id, endpoint_path=path, method=method,
                   check_type=CheckType.RATE_LIMIT, status=CaseStatus.QUEUED
               ))
               queued_cases.add(key)
   ```
2. Commit: `git commit -m "feat: add orchestrator heuristics for CORS/CSRF/XSS/CRLF/SSTI/RATE_LIMIT"`

---

## Phase 5: Verification

### Task 21: Verify all 17 scanners load

**Steps:**
1. Run the full scanner loading test:
   ```bash
   cd APEX-main/apex-dynamic-service
   python -c "
   from app.scanner_core.context import ScanContext
   from app.scanners.base import BaseScanner
   import importlib, pkgutil, app.scanners as pkg
   from inspect import isclass
   ctx = ScanContext(target_url='http://localhost')
   count = 0
   for _, name, _ in pkgutil.iter_modules(pkg.__path__, pkg.__name__ + '.'):
       if 'base' in name: continue
       mod = importlib.import_module(name)
       for attr_name in dir(mod):
           attr = getattr(mod, attr_name)
           if isclass(attr) and issubclass(attr, BaseScanner) and attr is not BaseScanner:
               s = attr(ctx)
               assert s.scan_id.startswith('APEX-'), f'{s.scan_id} not rebranded'
               count += 1
               print(f'  OK: {s.scan_id} ({s.name})')
   print(f'Total: {count} scanners loaded')
   assert count == 17, f'Expected 17, got {count}'
   "
   ```
   Expected: 17 scanners listed, all with `APEX-*` IDs, zero errors.

2. Verify no ZAP references remain:
   ```bash
   cd APEX-main/apex-dynamic-service
   grep -rni "zap" app/ --include="*.py" | grep -iv "x-xss" | grep -iv "csrftoken"
   ```
   Expected: No output (zero matches).

3. Commit: `git commit -m "verify: all 17 APEX scanners load, zero external references"`

---

### Task 22: Final cleanup

**Steps:**
1. Verify `docker-compose.yml` no longer references ZAP-python.
2. Verify `Dockerfile` needs no changes (scanners are inside `/app` now).
3. Tag completion: `git commit -m "feat: unified APEX scanner engine complete — 17 scanners"`
