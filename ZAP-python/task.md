# Task Checklist: ZAP-python Porting

## Phase 1: Planning & Setup
- [x] Analyze `zaproxy-main` architecture.
- [x] Clone `zap-extensions` for vulnerability logic.
- [x] Setup Python project structure (Engine, CLI, Scanners).
- [x] Implement Basic Logic (Spec Parser, Headers Scanner).

## Phase 2: Core Vulnerabilities (OWASP API Top 10)
- [x] **API8: Injection** - SQLi (Error/Time), NoSQLi (MongoDB), JSON Body Recursion.
- [x] **API1: BOLA** - Ported `UsernameIdorScanRule` (Passive Hash Check).
- [x] **API2: Broken Auth** - Ported `JwtScanRule` (Custom 'None' & Sig Exclusion).
- [x] **API3: Mass Assignment** - Implemented custom scanner with differential analysis.
- [x] **API7: Security Misconfiguration** - Enhance Headers Scanner.
- [x] **API7: Security Misconfiguration** - Enhance Headers Scanner.
- [x] **Reporting** - Structured JSON/Markdown reports with detailed evidence mapping.
- [ ] **API10: SSRF** - Implement `SSRFScanner`.
    - [ ] Port logic from ZAP extensions (Metadata, Localhost).
    - [ ] Implement detection heuristics (Response time, Reflected content).

## Phase 3: Verification & Integration
- [x] Deploy `crAPI` target for testing.
- [x] Verify `ZAP-python` against `crAPI` (Basic Scan).
- [x] Verify `ZAP-python` against `crAPI` (Authenticated Scan).
- [ ] Dockerize `ZAP-python`.
- [ ] Integrate into APEX Dashboard.

## Scan Results (crAPI)
- **Scanners Run**: Headers, SQLi, IDOR (Passive).
- **Findings**: 2450 (Deduplicated Unique Findings).
- **SQLi Status**: NoSQL Logic Bypasses detected (Critical).
- **Authentication**: JWT 'None' Algo and Signature Exclusion exploits verified.
- **IDOR Status**: No passive hash leakage found.
