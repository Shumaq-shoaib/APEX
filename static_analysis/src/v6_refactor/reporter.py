# -*- coding: utf-8 -*-
import json
import os
import logging
from datetime import datetime
from typing import Dict, Any, List, Tuple
from xml.etree.ElementTree import Element, SubElement, tostring

from .config import CONFIG, UTC_TZ
from .models import OasDetails
from .rules import VULNERABILITY_MAP

def generate_json_report(details: OasDetails, result: Dict[str, Any], out_path: str, explain: bool=False) -> None:
    """
    Write a JSON report with a top-level header (meta) similar to your v12 output,
    while preserving existing fields. Also injects help_url/examples/fix_recipes into findings.
    """
    # 1) Build header/meta
    info = details.get_info() or {}
    spec_path = details.spec().get("__file_path__", "N/A")
    meta = {
        "tool": "APEX OpenAPI Analyzer",
        "tool_version": "v6.0.0",
        "generated": datetime.now(UTC_TZ).isoformat(),
        "spec_file": os.path.basename(spec_path) if isinstance(spec_path, str) else "N/A",
        "api_title": info.get("title", "N/A"),
        "api_version": info.get("version", "N/A"),
        "profile": CONFIG.get("profile", "default")
    }

    # 2) Prepare endpoints as an array (and keep dict for back-compat)
    endpoints_arr: List[Dict[str, Any]] = []
    for ep_key, data in (result.get("endpoints") or {}).items():
        vulns = data.get("vulnerabilities", [])
        # inject rule help metadata per finding
        for v in vulns:
            meta_map = VULNERABILITY_MAP.get(v.get("rule_key"), {})
            if meta_map.get("help_url"):
                v["help_url"] = meta_map["help_url"]
            if meta_map.get("examples"):
                v.setdefault("examples", meta_map["examples"])
            if meta_map.get("fix_recipes"):
                v.setdefault("fix_recipes", meta_map["fix_recipes"])
        endpoints_arr.append({
            "endpoint": ep_key,
            "vulnerabilities": vulns
        })

    # 3) Assemble final document (keeps old keys + adds header)
    out_doc = {
        "meta": meta,
        "summary": result.get("summary", {}),
        "summary_raw": result.get("summary_raw", {}),
        "endpoints": endpoints_arr,                     # new, array form
        "endpoints_by_key": result.get("endpoints", {}),# legacy dict form for back-compat
        "dynamic_followups": result.get("dynamic_followups", [])
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out_doc, f, ensure_ascii=False, indent=2)
    logging.info(f"JSON report saved to {out_path}")


def generate_markdown_report(details: OasDetails, result: Dict[str, Any], output_file: str, explain: bool) -> None:
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"# 🛡️ APEX Static Analysis Report\n\n")
        f.write(f"- **File Analyzed**: `{os.path.basename(details.spec().get('__file_path__', 'N/A'))}`\n")
        info = details.get_info()
        f.write(f"- **API Title**: {info.get('title', 'N/A')}\n")
        f.write(f"- **API Version**: {info.get('version', 'N/A')}\n")
        f.write(f"- **Generated**: {datetime.now(UTC_TZ).isoformat()}\n\n")

        summary = result.get("summary", {})
        f.write("## Vulnerability Summary (Normalized)\n\n")
        f.write("| Severity | Count |\n|----------|-------|\n")
        f.write(f"| Critical | {summary.get('Critical', 0)} |\n")
        f.write(f"| High     | {summary.get('High', 0)} |\n")
        f.write(f"| Medium   | {summary.get('Medium', 0)} |\n")
        f.write(f"| Low      | {summary.get('Low', 0)} |\n")
        f.write(f"| **Total** | **{summary.get('total', 0)}** |\n\n")

        all_findings: List[Tuple[str, Dict[str, Any]]] = []
        for ep, data in result.get("endpoints", {}).items():
            for v in data.get("vulnerabilities", []):
                all_findings.append((ep, v))
        sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        all_findings.sort(key=lambda item: sev_rank.get(item[1].get("severity", "Low"), 3))

        current = None
        for ep, v in all_findings:
            sev = v.get("severity", "Low")
            if sev != current:
                current = sev
                f.write(f"### {sev} Severity Findings\n\n")
            desc = v.get("details", {}).get("description", "").strip()
            name = v.get("name", "Issue")
            ref  = v.get("owasp_ref", "N/A")
            f.write(f"- **[{name}]** ({ref}) — **Endpoint:** `{ep}`\n  - {desc}\n")
            if v.get("severity_original") and v["severity_original"] != sev:
                pol = v.get("severity_policy_note", "Severity normalized by APEX policy.")
                f.write(f"  - _Original:_ {v['severity_original']}; _Policy:_ {pol}\n")
            f.write(f"  - Fingerprint: `{v.get('fingerprint')}`\n")
            if explain and v.get("evidence"):
                f.write(f"  - Evidence: `{json.dumps(v['evidence'], ensure_ascii=False)}`\n")
            f.write("\n")

        dfu = result.get("dynamic_followups", [])
        if dfu:
            f.write("## Dynamic Follow-Ups (to run in authorized test environments)\n\n")
            for t in dfu:
                f.write(f"- **{t['title']}** — _Category:_ {t['category']}, _Priority:_ {t['priority']}\n")
                for req in t.get("suggested_requests", []):
                    f.write(f"  - `{req['method']} {req['url_template']}` — {req.get('notes','')}\n")
                if t.get("related_findings"):
                    f.write(f"  - Related findings: {', '.join(t['related_findings'])}\n")
                f.write("\n")
    logging.info(f"Markdown report saved to {output_file}")


def level_to_sarif(sev: str) -> str:
    return {"Critical":"error","High":"error","Medium":"warning","Low":"note"}.get(sev,"note")

def generate_sarif_report(details: OasDetails, result: Dict[str, Any], out_path: str) -> None:
    """
    Emit SARIF v2.1.0 with:
      - rule help metadata (helpUri at rule; help_url/examples/fix_recipes per-result)
      - a run-level properties.meta header mirroring the JSON report
      - run-level properties.summary and properties.summary_raw
      - tool.driver.version + semanticVersion
    """
    def _sarif_level(sev: str) -> str:
        sev = (sev or "").lower()
        if sev in ("critical", "high"): return "error"
        if sev == "medium": return "warning"
        return "note"

    # ---- build meta header (same as JSON) ----
    info = details.get_info() or {}
    spec_path = details.spec().get("__file_path__", "N/A")
    meta = {
        "tool": "APEX OpenAPI Analyzer",
        "tool_version": "v6.0.0",
        "generated": datetime.now(UTC_TZ).isoformat(),
        "spec_file": os.path.basename(spec_path) if isinstance(spec_path, str) else "N/A",
        "api_title": info.get("title", "N/A"),
        "api_version": info.get("version", "N/A"),
        "profile": CONFIG.get("profile", "default")
    }

    # ---- flatten findings ----
    flat: List[Dict[str, Any]] = []
    for _ep, data in result.get("endpoints", {}).items():
        flat.extend(data.get("vulnerabilities", []))

    # ---- rules map with help ----
    rules_map: Dict[str, Dict[str, Any]] = {}
    for v in flat:
        rk = v.get("rule_key", "unknown_rule")
        meta_m = VULNERABILITY_MAP.get(rk, {})
        help_url = meta_m.get("help_url")
        if rk not in rules_map:
            rules_map[rk] = {
                "id": rk,
                "name": meta_m.get("name", rk),
                "shortDescription": {"text": meta_m.get("name", rk)},
                "fullDescription": {"text": meta_m.get("recommendation", meta_m.get("name", rk))},
                "helpUri": help_url if help_url else None,
                "help": {"text": meta_m.get("recommendation", ""), "markdown": meta_m.get("recommendation", "")},
                "properties": {
                    "owasp_api_top_10": meta_m.get("owasp_api_top_10"),
                    "default_severity": meta_m.get("severity", "Low"),
                },
                "defaultConfiguration": {
                    "level": _sarif_level(meta_m.get("severity", "Low"))
                }
            }

    # ---- results with per-result properties ----
    sarif_results: List[Dict[str, Any]] = []
    for v in flat:
        rk = v.get("rule_key", "unknown_rule")
        meta_m = VULNERABILITY_MAP.get(rk, {})
        help_url = meta_m.get("help_url")
        ex_list = meta_m.get("examples")
        fix_list = meta_m.get("fix_recipes")

        sev = v.get("severity") or meta_m.get("severity", "Low")
        msg = v.get("details", {}).get("description") or v.get("name") or meta_m.get("name", rk)

        jp = (v.get("details") or {}).get("json_pointer") or "/"
        loc = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": details.spec().get("__file_path__", "<spec>"),
                },
                "region": {"message": jp}
            }
        }

        res: Dict[str, Any] = {
            "ruleId": rk,
            "level": _sarif_level(sev),
            "message": {"text": msg},
            "locations": [loc],
            "properties": {
                "severity": sev,
                "severity_score": v.get("severity_score"),
                "endpoint": v.get("details", {}).get("endpoint") or v.get("endpoint"),
                "json_pointer": jp,
                "owasp_ref": v.get("owasp_ref") or meta_m.get("owasp_api_top_10"),
                "fingerprint": v.get("fingerprint"),
                "recommendation": v.get("recommendation") or meta_m.get("recommendation"),
            }
        }
        if help_url:
            res["properties"]["help_url"] = help_url
        if ex_list:
            res["properties"]["examples"] = ex_list
        if fix_list:
            res["properties"]["fix_recipes"] = fix_list

        policy = v.get("policy") or {}
        if policy:
            res["properties"]["policy"] = policy
        if v.get("suppression"):
            res["properties"]["suppression"] = v["suppression"]
        if v.get("details", {}).get("evidence"):
            res["properties"]["evidence"] = v["details"]["evidence"]

        if v.get("fingerprint"):
            res["partialFingerprints"] = {"primaryLocationLineHash": v["fingerprint"]}

        sarif_results.append(res)

    # ---- finalize rules array ----
    sarif_rules = []
    for rk, r in rules_map.items():
        if r.get("helpUri") is None:
            r.pop("helpUri", None)
        sarif_rules.append(r)

    # ---- assemble SARIF with meta + summaries ----
    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "APEX OpenAPI Analyzer",
                        "version": "v6.0.0",          # visible version
                        "semanticVersion": "6.0.0",   # semver for tools
                        "informationUri": "https://apex.example/tools/oas-analyzer",
                        "rules": sarif_rules
                    }
                },
                # Custom header & counts mirrored from JSON report
                "properties": {
                    "meta": meta,
                    "summary": result.get("summary", {}),
                    "summary_raw": result.get("summary_raw", {})
                },
                "results": sarif_results
            }
        ]
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sarif_doc, f, ensure_ascii=False, indent=2)
    logging.info(f"SARIF report saved to {out_path}")


def generate_junit_report(details: OasDetails, result: Dict[str, Any], output_file: str) -> None:
    suite = Element("testsuite")
    suite.set("name", "APEX OAS Analyzer")
    counts = result.get("summary", {})
    total = counts.get("total", 0)
    suite.set("tests", str(total))
    suite.set("failures", str(total))  # treat all findings as failures for CI surfaces
    suite.set("errors", "0")
    suite.set("time", "0")

    for ep, data in result.get("endpoints", {}).items():
        for v in data.get("vulnerabilities", []):
            case = SubElement(suite, "testcase")
            case.set("classname", v.get("rule_key"))
            case.set("name", f"{v.get('severity')} | {v.get('name')} | {ep}")
            fail = SubElement(case, "failure")
            fail.set("message", v["details"]["description"])
            fail.text = json.dumps({
                "fingerprint": v.get("fingerprint"),
                "recommendation": v.get("recommendation"),
                "blocking": v.get("policy", {}).get("blocking", False)
            })

    xml_bytes = tostring(suite, encoding="utf-8")
    with open(output_file, "wb") as f:
        f.write(xml_bytes)
    logging.info(f"JUnit report saved to {output_file}")


def _pretty_print(details: OasDetails, result: Dict[str, Any], verbose: bool=False, explain: bool=False) -> None:
    s = result.get("summary", {})
    print("\n=== API Security Summary (Normalized) ===")
    print(f"Critical: {s.get('Critical',0)} | High: {s.get('High',0)} | Medium: {s.get('Medium',0)} | Low: {s.get('Low',0)} | Total: {s.get('total',0)}")

    if verbose:
        print("\n=== Parsed OAS Details ===")
        eps = details.endpoints
        print(f"Endpoints ({len(eps)}):")
        for ep in eps:
            print(f"  {ep['method']} {ep['path']}: {ep.get('summary', 'No summary')}")
        print(f"\nSecurity Schemes ({len(details.get_security_schemes())}): {', '.join(details.get_security_schemes().keys())}")
        servers = [s['url'] for s in details.get_servers() if isinstance(s, dict) and 'url' in s]
        print(f"Schemas ({len(details.get_schemas())})\nServers: {', '.join(servers)}\n")

    print("\n=== Findings by Endpoint ===")
    for endpoint, data in result.get("endpoints", {}).items():
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            continue
        print(f"\n[{endpoint}]  ({len(vulns)} finding(s))")
        sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        for v in sorted(vulns, key=lambda x: sev_rank.get(x.get("severity","Low"),3)):
            sev = v.get("severity", "Low")
            name = v.get("name", "Issue")
            desc = (v.get("details") or {}).get("description", "")
            orig = v.get("severity_original")
            tail = f" (original {orig})" if orig and orig != sev else ""
            pol = v.get("severity_policy_note")
            pol_tail = f" | policy: {pol}" if pol else ""
            print(f"  - [{sev}] {name}{tail}: {desc}{pol_tail}  | fp={v.get('fingerprint')}")

            if explain:
                # show exact JSON Pointer (if populated)
                jp = (v.get("details") or {}).get("json_pointer")
                if jp:
                    print(f"      pointer: {jp}")

                # suppression block (as requested)
                supp = (v.get("policy") or {}).get("suppressed", False)
                if supp:
                    sup = v.get("suppression", {}) or {}
                    print(f"      ↳ suppressed: true ({sup.get('reason','')})")
                    if sup.get("expiry"):
                        print(f"         expires: {sup['expiry']}")
                    if sup.get("justification"):
                        print(f"         note: {sup['justification']}")

                # evidence (if present)
                if v.get("evidence"):
                    try:
                        print(f"      evidence: {json.dumps(v['evidence'], ensure_ascii=False)}")
                    except Exception:
                        print(f"      evidence: {v['evidence']}")
    print("")

def _write_telemetry(result: Dict[str, Any]) -> None:
    try:
        os.makedirs(".apex", exist_ok=True)
        path = os.path.join(".apex","telemetry.jsonl")
        with open(path, "a", encoding="utf-8") as f:
            for ep, data in result.get("endpoints", {}).items():
                for v in data.get("vulnerabilities", []):
                    f.write(json.dumps({
                        "ts": datetime.now(UTC_TZ).isoformat(),
                        "rule": v.get("rule_key"),
                        "sev": v.get("severity"),
                        "fp": v.get("fingerprint")
                    }) + "\n")
    except Exception as e:
        logging.debug(f"telemetry write failed: {e}")
