# Unified APEX Scanner Engine — Design Document

Consolidate ZAP-python (external), Astra modules, and APEX engine into a **single native scanning engine** under APEX branding. Remove all external naming, eliminate duplication, and establish one clean scanner architecture.

---

## Problem

Currently, APEX's dynamic analysis has fragmented origins:
- `ZAP-python/` — 10 scanners in a **separate directory**, imported via `sys.path` hack
- `Astra/` — 16 modules in a **completely separate project**, not yet integrated
- Scanner IDs use `API-*` prefix, code references "ZAP", "zap", "Astra" throughout
- Docker mounts `ZAP-python` as a separate volume
- Security headers logic duplicated between ZAP-python and Astra

## Goal

One native scanner package at `apex-dynamic-service/app/scanners/` with:
- All existing ZAP-python scanner logic **moved** inline (rebranded)
- All Astra-unique logic **ported** as new scanners
- All duplicated logic **merged** (best of both)
- Zero external references — everything is "APEX"

---

## Architecture (After)

```
apex-dynamic-service/
  app/
    scanners/               ← NEW unified package (was ZAP-python/scanners)
      __init__.py
      base.py               ← BaseScanner ABC (moved from ZAP-python)
      # --- Ported from ZAP-python (rebranded) ---
      idor_active.py         ← was api_active_idor.py
      idor_passive.py        ← was api_idor.py
      injection_sqli.py      ← was api_injection.py (SQLi logic)
      injection_cmd.py       ← was api_command_injection.py
      jwt_scan.py            ← was api_jwt.py
      mass_assignment.py     ← was api_mass_assignment.py
      redirect.py            ← was api_redirect.py
      ssrf.py                ← was api_ssrf.py
      xxe.py                 ← was api_xxe.py
      # --- Merged (ZAP-python + Astra best-of-both) ---
      security_headers.py    ← MERGED: ZAP-python api_headers + Astra security_headers_missing
      # --- New from Astra ---
      cors.py                ← NEW from Astra/modules/cors.py
      csrf.py                ← NEW from Astra/modules/csrf.py
      crlf.py                ← NEW from Astra/modules/crlf.py
      rate_limit.py          ← NEW from Astra/modules/rate_limit.py
      ssti.py                ← NEW from Astra/modules/template_injection.py (native reimpl)
      xss.py                 ← NEW from Astra/modules/xss.py
      broken_auth.py         ← NEW from Astra/modules/broken_auth.py
    scanner_utils/           ← NEW unified utils (was ZAP-python/utils)
      __init__.py
      http.py                ← was http_utils.py (rename)
      payloads.py            ← was payloads.py + Astra Payloads/ (merged)
      detection.py           ← was detection.py + new patterns (merged)
    scanner_core/            ← NEW unified core (was ZAP-python/core)
      __init__.py
      context.py             ← was ZAP-python/core/context.py (rename references)
    services/
      engine.py              ← REBRANDED: "AttackEngine" stays, all ZAP refs removed
      orchestrator.py        ← UPDATED: new CheckType heuristics
      ...
```

---

## Scanner ID Rename Map

| Old ID (ZAP-python) | New ID (APEX) | Scanner File |
|---|---|---|
| `API-ACTIVE-IDOR` | `APEX-IDOR-ACTIVE` | `idor_active.py` |
| `API-IDOR-PASSIVE` | `APEX-IDOR-PASSIVE` | `idor_passive.py` |
| `API-SQLI` | `APEX-SQLI` | `injection_sqli.py` |
| `API-CMD-INJ` | `APEX-CMD-INJ` | `injection_cmd.py` |
| `API-JWT-SCAN` | `APEX-JWT` | `jwt_scan.py` |
| `API-MASS-ASSIGN` | `APEX-MASS-ASSIGN` | `mass_assignment.py` |
| `API-REDIRECT` | `APEX-REDIRECT` | `redirect.py` |
| `API-SSRF` | `APEX-SSRF` | `ssrf.py` |
| `API-XXE` | `APEX-XXE` | `xxe.py` |
| `API-SEC-HEADERS` | `APEX-SEC-HEADERS` | `security_headers.py` |
| *(new)* | `APEX-CORS` | `cors.py` |
| *(new)* | `APEX-CSRF` | `csrf.py` |
| *(new)* | `APEX-CRLF` | `crlf.py` |
| *(new)* | `APEX-RATE-LIMIT` | `rate_limit.py` |
| *(new)* | `APEX-SSTI` | `ssti.py` |
| *(new)* | `APEX-XSS` | `xss.py` |
| *(new)* | `APEX-BROKEN-AUTH` | `broken_auth.py` |

**Total: 17 scanners** (10 moved + 1 merged + 6 new)

---

## Overlap / Merge Strategy

| Area | ZAP-python | Astra | Resolution |
|---|---|---|---|
| **Security Headers** | Checks CSP, X-Content-Type-Options, HSTS (3 headers) | Checks CSP, X-XSS-Protection, X-Frame-Options, HSTS, cookies, version disclosure (6+ checks) | **Merge**: combine into one scanner with all checks from Astra (more comprehensive) + ZAP-python evidence format |
| **SSRF** | Cloud metadata, localhost probing, IP obfuscation (comprehensive) | Param-name-based detection only (Payloads/ssrf.txt is just param names) | **Keep ZAP-python version** — it's far more thorough |
| **SQLi** | Error-based + polyglot payloads | Basic injection with Celery | **Keep ZAP-python version** — better payloads and detection |
| **XXE** | 4 templates (basic, parameter, OAST, DoS) | Similar basic templates | **Keep ZAP-python version** |
| **Open Redirect** | 14 URL variants + 3 header variants | Fetch redirection param names + checks | **Keep ZAP-python version** |
| **Auth/JWT** | JWT signature bypass, expired token checks | Session fixation, weak password, credential-in-URL | **Complement**: keep JWT scanner + add broken_auth.py as new scanner |

---

## Changes by File

### Files to CREATE (new)

| File | Source | Description |
|---|---|---|
| `app/scanners/__init__.py` | — | Package init |
| `app/scanners/base.py` | ZAP-python `base.py` | BaseScanner ABC, unchanged logic |
| `app/scanners/idor_active.py` | ZAP `api_active_idor.py` | Rename class + scan_id |
| `app/scanners/idor_passive.py` | ZAP `api_idor.py` | Rename class + scan_id |
| `app/scanners/injection_sqli.py` | ZAP `api_injection.py` | Rename class + scan_id |
| `app/scanners/injection_cmd.py` | ZAP `api_command_injection.py` | Rename class + scan_id |
| `app/scanners/jwt_scan.py` | ZAP `api_jwt.py` | Rename class + scan_id |
| `app/scanners/mass_assignment.py` | ZAP `api_mass_assignment.py` | Rename class + scan_id |
| `app/scanners/redirect.py` | ZAP `api_redirect.py` | Rename class + scan_id |
| `app/scanners/ssrf.py` | ZAP `api_ssrf.py` | Rename class + scan_id |
| `app/scanners/xxe.py` | ZAP `api_xxe.py` | Rename class + scan_id |
| `app/scanners/security_headers.py` | ZAP `api_headers.py` + Astra `security_headers_missing.py` | **Merged** — all checks from both, APEX evidence format |
| `app/scanners/cors.py` | Astra `cors.py` | New: evil origins, credential reflection |
| `app/scanners/csrf.py` | Astra `csrf.py` | New: token removal/tampering, Content-Type bypass |
| `app/scanners/crlf.py` | Astra `crlf.py` | New: 16 CRLF payloads |
| `app/scanners/rate_limit.py` | Astra `rate_limit.py` | New: burst requests on auth endpoints |
| `app/scanners/ssti.py` | Astra `template_injection.py` | New: native math-expr detection (replaces tplmap) |
| `app/scanners/xss.py` | Astra `xss.py` | New: 4 injection vectors |
| `app/scanners/broken_auth.py` | Astra `broken_auth.py` | New: session fixation, token stripping |
| `app/scanner_utils/__init__.py` | — | Package init |
| `app/scanner_utils/http.py` | ZAP `utils/http_utils.py` | Move + rename |
| `app/scanner_utils/payloads.py` | ZAP `utils/payloads.py` + Astra `Payloads/` | Move + merge payloads |
| `app/scanner_utils/detection.py` | ZAP `utils/detection.py` | Move + add new patterns |
| `app/scanner_core/__init__.py` | — | Package init |
| `app/scanner_core/context.py` | ZAP `core/context.py` | Move, rename docstrings |

### Files to MODIFY

| File | Changes |
|---|---|
| `app/models/dynamic.py` | Add `CheckType` values: `CORS`, `CSRF`, `CRLF`, `RATE_LIMIT`, `SSTI` |
| `app/services/engine.py` | Remove ZAP-python imports/references, import from `app.scanners.*`, rename `_load_zap_scanners` → `_load_scanners`, update scan_id mapping, rebrand all log messages and variable names |
| `app/services/orchestrator.py` | Add heuristic test-case generation for new CheckTypes |
| `app/services/reporting.py` | Add CVSS scores + remediation for CORS, CSRF, CRLF, RATE_LIMIT, SSTI |
| `app/main.py` | Remove `sys.path` hack for ZAP-python — scanners are now native imports |
| `Dockerfile` | No changes needed (scanners are inside `/app` now) |
| `docker-compose.yml` | **Remove** `- ./ZAP-python:/ZAP-python` volume mount |

### Files/Dirs to DEPRECATE (after migration)

| Path | Action |
|---|---|
| `ZAP-python/` directory | No longer imported — code has been moved into `app/scanners/` etc. Can be deleted or kept as archive |

---

## New Scanner Details (from Astra)

### `cors.py` — `APEX-CORS`
- Generate evil origins (`http://evil.com`, `<target>.evil.com`)
- Send OPTIONS/GET with `Origin`, check `Access-Control-Allow-Origin` reflection
- Check `Access-Control-Allow-Credentials: true` (severity escalation)
- **Severity:** High (reflected+credentials), Medium (wildcard), Low (reflected-only)

### `csrf.py` — `APEX-CSRF`
- POST/PUT/DELETE only; detect CSRF headers and body params
- Test: remove CSRF header, tamper token, change Content-Type to `text/plain`
- **Severity:** High (bypassed), Medium (Content-Type bypass only)

### `crlf.py` — `APEX-CRLF`
- Inject 16 CRLF payloads into query params and body fields
- Check response headers for injected `CRLF-Test` header
- **Severity:** High (header injection), Medium (body reflection)

### `rate_limit.py` — `APEX-RATE-LIMIT`
- Identify sensitive params (password, pin, otp, cvv)
- Send 50 rapid requests with random values
- Flag if no 429/rate-limit rejection
- **Severity:** High (auth endpoints), Medium (other)

### `ssti.py` — `APEX-SSTI`
- Inject `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, etc.
- Check for `49` or `7777777` in response
- Engine-specific: Jinja2 `{{config}}`, Twig, Mako
- **Severity:** Critical (code exec), High (expression reflected)

### `xss.py` — `APEX-XSS`
- 4 vectors: query params, URI path, body fields, reflected headers
- 10 payloads + DOM markers
- Impact assessment via CSP/X-Content-Type-Options checks
- **Severity:** High (XSS + no CSP), Medium (mitigated)

### `broken_auth.py` — `APEX-BROKEN-AUTH`
- Session fixation: check URL for `sessionid=`, `id=`, `key=`
- Token stripping: replay without Authorization, flag if 2xx
- Complements existing `APEX-JWT`
- **Severity:** High (token bypass), Medium (session fixation)

### `security_headers.py` — `APEX-SEC-HEADERS` (MERGED)
Combined from ZAP-python (3 checks) + Astra (6+ checks):
- CSP, X-Content-Type-Options, HSTS *(from ZAP-python)*
- X-XSS-Protection (enabled + mode=block), X-Frame-Options, cookie security (Secure+HttpOnly), server version disclosure *(from Astra)*
- Evidence capture using APEX's `RequestRecord` *(from ZAP-python pattern)*

---

## `CheckType` → Scanner Mapping (final)

```python
{
    CheckType.BOLA:          ["APEX-IDOR-ACTIVE"],
    CheckType.BROKEN_AUTH:   ["APEX-JWT", "APEX-SEC-HEADERS", "APEX-BROKEN-AUTH"],
    CheckType.SQLI:          ["APEX-SQLI"],
    CheckType.INJECTION:     ["APEX-CMD-INJ"],
    CheckType.SSRF:          ["APEX-SSRF"],
    CheckType.DATA_EXPOSURE: ["APEX-IDOR-PASSIVE", "APEX-MASS-ASSIGN"],
    CheckType.XSS:           ["APEX-XSS"],
    CheckType.OTHER:         ["APEX-REDIRECT", "APEX-XXE"],
    # New types
    CheckType.CORS:          ["APEX-CORS"],
    CheckType.CSRF:          ["APEX-CSRF"],
    CheckType.CRLF:          ["APEX-CRLF"],
    CheckType.RATE_LIMIT:    ["APEX-RATE-LIMIT"],
    CheckType.SSTI:          ["APEX-SSTI"],
}
```

---

## Orchestrator Heuristics (test-case generation)

New rules added to `SessionOrchestrator.run_scan_background()`:

| CheckType | When to Queue |
|---|---|
| `CORS` | Every endpoint |
| `CSRF` | POST/PUT/DELETE endpoints |
| `CRLF` | Endpoints with query params or body fields |
| `XSS` | Endpoints with string parameters |
| `RATE_LIMIT` | POST/PUT endpoints with body params named password/pin/otp/cvv |
| `SSTI` | Endpoints with string parameters |
| `BROKEN_AUTH` | Already queued via existing non-public-path logic |

---

## Verification Plan

### Automated Tests
1. **Import test** — Verify all 17 scanners load without errors:
   ```
   cd APEX-main/apex-dynamic-service
   python -c "from app.scanners import base; print('OK')"
   ```
2. **Unit tests** — We can add `app/tests/test_scanners.py` with mock HTTP responses for each of the 7 new scanners to verify they produce findings on vulnerable responses and no false positives on clean responses.
   ```
   cd APEX-main/apex-dynamic-service
   python -m pytest app/tests/test_scanners.py -v
   ```

### Manual Verification
- Start APEX services (`docker-compose up -d`)
- Upload an API spec, run a dynamic scan against a test target
- Verify new check types (CORS, CSRF, XSS, etc.) appear in scan results on the dashboard
- Confirm the `ZAP-python` volume mount is no longer needed

> [!IMPORTANT]
> We should verify this together: after implementation, I'll run the import test and you can verify the dashboard shows new finding types.
