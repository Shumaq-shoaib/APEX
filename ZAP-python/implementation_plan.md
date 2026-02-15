# IMPLMENTATION_PLAN.md

## Goal
Create a lightweight, Python-based CLI tool (`active-scan-cli`) that mimics the core functionality of OWASP ZAP's **API Scanning** engine. The tool will focus on enforcing **OWASP API Security Top 10** vulnerabilities without the overhead of ZAP's Swing GUI or legacy dependencies.

This is **Phase 1** of a larger initiative to integrate this scanner into the **APEX** platform.

## Architecture
The project will follow a modular architecture inspired by ZAP's internal design (`ActiveScan`, `Plugins`, `Context`) but simplified for a headless, API-first workflow.

### Core Components
1.  **CLI Entry Point**:
    *   Uses `typer` or `argparse` for a modern command-line interface.
    *   Commands: `scan`, `list-rules`, `analyze-spec`.
2.  **Engine (`core/`)**:
    *   **Context**: Manages state, session tokens, and target definitions.
    *   **Spider/Parsers**:
        *   **OpenAPI Parser**: Uses `prance` or `openapi-spec-validator` to read Swagger/OpenAPI specs and generate a list of "Testable Endpoints".
        *   Replaces ZAP's crawling spider with a spec-driven approach (more accurate for APIs).
    *   **AttackRunner**: The orchestrator (equivalent to ZAP's `ActiveScanController`) that iterates over endpoints and dispatches `Plugins`.
3.  **Plugins (`scanners/`)**:
    *   Base `Scanner` class.
    *   Individual vulnerability checks implemented as classes.
    *   **Focus**: OWASP API Top 10 (e.g., BOLA, Broken Auth, Excessive Data Exposure).
4.  **Reporting**:
    *   Generates JSON/Markdown reports compatible with APEX's dashboard.

## Phase 1: feature Scope (OWASP API Top 10)
We will "simulate" (implement) the following high-impact checks in Python:

| OWASP Category | ZAP Equivalent Logic | Python Implementation Strategy |
| :--- | :--- | :--- |
| **API1: BOLA** | ID Fuzzing / Auth Matrix | Mutate `id` parameters in URLs/Bodies; replay request with different user tokens. |
| **API2: Broken Auth** | Header Analysis | Check for missing `Authorization` headers, weak tokens (JWT none algorithm). |
| **API3: Broken Object Prop.** | Mass Assignment | Send unexpected fields (e.g., `is_admin: true`) in POST/PUT requests. |
| **API4: Unrestricted Rate Limiting** | Spamming | (Optional) Send bursts of requests to measure 429 responses. |
| **API8: Injection** | Active Scan Rules | Inject SQLi/Command payloads (`'`, `OR 1=1`, `; ls`) into parameters. |

## Migration Strategy (Java -> Python)
We are not converting code line-by-line. We are porting **Verification Logic**.

1.  **Extract Patterns**: Analyze ZAP's Java `ascan` rules to see exact payloads (e.g., polyglot payloads).
2.  **Re-implement**: Write Python functions using `requests` to send these payloads.
3.  **Validate**: Compare results against a known vulnerable target (crAPI).

## File Structure
```text
ZAP-python/
├── main.py                 # CLI Entry point
├── requirements.txt        # Dependencies (requests, typer, prance, rich)
├── core/
│   ├── engine.py           # Attack Runner
│   ├── context.py          # Session/Auth persistence
│   └── parser.py           # OpenAPI Spec parser
└── scanners/
    ├── base.py             # Abstract Base Class for rules
    ├── api_bola.py         # BOLA checks
    ├── api_sqli.py         # Injection checks
    └── scanner_loader.py   # Dynamic plugin loader
```

## Next Steps
1.  Initialize the Python project structure.
2.  Implement the `OpenAPI Parser` logic to generate a "Attack Surface".
3.  Implement the `BOLA` scanner as a proof-of-concept.
