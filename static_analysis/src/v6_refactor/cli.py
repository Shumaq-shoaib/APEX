import argparse
import sys
import os
import logging
import yaml
import json
from datetime import datetime

# Adjust path to find the package if running directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

from v6_refactor.config import CONFIG, load_config, UTC_TZ
from v6_refactor.models import OasDetails
from v6_refactor.blueprint import generate_blueprint
from v6_refactor.rules import (
    apply_policy_pack, load_rule_plugins, spectral_ingest, spectral_export,
    build_yaml_rule_fn, VULNERABILITY_MAP, RULE_FUNCTIONS
)
from v6_refactor.scanner import analyze_spec, analyze_spec_incremental, NDJSONWriter
from v6_refactor.helpers import load_baseline
from v6_refactor.reporter import (
    generate_json_report, generate_markdown_report, generate_sarif_report,
    generate_junit_report, _pretty_print, _write_telemetry
)

def main():
    parser = argparse.ArgumentParser(description="APEX OpenAPI static analyzer → v6.0.0 (Refactored)")
    parser.add_argument("oas_path", help="Path to OpenAPI spec (.json/.yaml)")
    parser.add_argument("--config", help="Optional YAML with base settings", default=None)
    parser.add_argument("--policy-pack", action="append", default=[], help="YAML policy pack (can repeat)")
    parser.add_argument("--rules-path", action="append", default=[], help="Directory with Python rule plugins (*.py)")

    parser.add_argument("--spectral-in", help="Ingest Spectral ruleset (severities/toggles) into APEX")
    parser.add_argument("--spectral-out", help="Export APEX ruleset as Spectral YAML file")
    parser.add_argument("--blueprint-out", help="Export Scan Blueprint for Dynamic Engine (JSON)")

    parser.add_argument("--output", choices=["pretty", "json", "markdown", "sarif", "junit"], default="pretty",
                        help="pretty=console, json/markdown/sarif/junit=write file")
    parser.add_argument("--out-file", help="Path to write output file when not 'pretty'")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    # Legacy threshold
    parser.add_argument("--fail-on", choices=["none", "low", "medium", "critical"], default="none",
                        help="(Legacy) Exit non-zero if at least one finding at or above threshold exists.")
    # Quotas
    parser.add_argument("--max-critical", type=int, default=10**9)
    parser.add_argument("--max-high", type=int, default=10**9)
    parser.add_argument("--max-medium", type=int, default=10**9)
    parser.add_argument("--max-low", type=int, default=10**9)
    
    parser.add_argument("--incremental", action="store_true",
                        help="Stream analysis incrementally (NDJSON findings).")
    parser.add_argument("--threads", type=int, default=CONFIG.get("threads", 8),
                        help="Number of worker threads for parallel-safe rules.")


    parser.add_argument("--verbose", action="store_true", help="Print parsed endpoints/schemas/servers overview in pretty mode.")
    parser.add_argument("--explain", action="store_true", help="Show evidence for why each rule fired.")

    parser.add_argument("--baseline", help="Path to previous JSON report for new/worsened compare", default=None)
    parser.add_argument("--profile", choices=["default","production","sandbox","pci","hipaa"], default="default",
                        help="Severity profile to adjust normalized severities.")
    parser.add_argument("--telemetry", action="store_true",
                    help="Emit anonymized per-finding stats to .apex/telemetry.jsonl")
    parser.add_argument("--require-signed-plugins", action="store_true",
                    help="Only load plugins with valid .sig (sha256:<hex>)")
    parser.add_argument("--sandbox-plugins", action="store_true",
                    help="Run plugins in a restricted worker process")
    


    args = parser.parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(levelname)s: %(message)s")

    # base config + packs + spectral
    if args.config:
        load_config(args.config)
    
    CONFIG["profile"] = args.profile
    CONFIG["threads"] = args.threads   
    CONFIG["require_signed_plugins"] = getattr(args, "require_signed_plugins", False)
    CONFIG.setdefault("parallel_checks", True)
    CONFIG["sandbox_plugins"] = getattr(args, "sandbox_plugins", False)
    logging.debug(f"Active APEX profile: {CONFIG['profile']}")
    
    
    pack_info = apply_policy_pack(args.policy_pack)
    yaml_rules = pack_info.get("yaml_rules") or []

    if args.spectral_in:
        spectral_ingest(args.spectral_in)

    # Built-ins are already registered in rules.py import

    # Register YAML DSL rules
    for ydef in yaml_rules:
        try:
            key, meta, fn = build_yaml_rule_fn(ydef)
            VULNERABILITY_MAP[key] = {
                "owasp_api_top_10": meta["owasp_api_top_10"],
                "name": meta["name"],
                "severity": meta["severity"],
                "prefix": meta["prefix"],
                "recommendation": meta["recommendation"]
            }
            RULE_FUNCTIONS[key] = fn
        except Exception as e:
            logging.error(f"Invalid YAML rule {ydef}: {e}")
        VULNERABILITY_MAP[key] = meta
        RULE_FUNCTIONS[key] = fn
    
    if args.spectral_out:
        spectral_export(args.spectral_out)
        return
    
    # === Load Spec ===
    try:
        with open(args.oas_path, "r", encoding="utf-8") as f:
            ext = os.path.splitext(args.oas_path)[1].lower()
            if ext in (".json",):
                spec_doc = json.load(f)
            else:
                spec_doc = yaml.safe_load(f)
        if not isinstance(spec_doc, dict):
            logging.error("Spec is not a dictionary.")
            sys.exit(1)
        # attach path
        spec_doc["__file_path__"] = os.path.abspath(args.oas_path)
    except Exception as e:
        logging.error(f"Failed to read spec: {e}")
        sys.exit(1)

    details = OasDetails(spec_doc)

    # === Analysis ===
    if args.incremental:
        if args.output == "pretty":
            logging.warning("Incremental mode with pretty output is noisy. Suggest writing to file via --output json --out-file ...")
        writer = NDJSONWriter(args.out_file or "/dev/stdout")
        analyze_spec_incremental(details, writer, explain=args.explain, threads=args.threads)
        writer.close()
        return

    result = analyze_spec(details, explain=args.explain)

    if args.blueprint_out:
        bp = generate_blueprint(details, result)
        try:
            with open(args.blueprint_out, "w", encoding="utf-8") as f:
                json.dump(bp, f, indent=2)
            logging.info(f"Blueprint exported to {args.blueprint_out}")
        except Exception as e:
            logging.error(f"Failed to write blueprint: {e}")

    # === Reporting ===
    if args.telemetry:
        _write_telemetry(result)

    if args.output == "pretty":
        _pretty_print(details, result, verbose=args.verbose, explain=args.explain)
    elif args.output == "json":
        if not args.out_file:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            generate_json_report(details, result, args.out_file, explain=args.explain)
    elif args.output == "markdown":
        if not args.out_file:
            logging.error("Markdown output requires --out-file")
        else:
            generate_markdown_report(details, result, args.out_file, explain=args.explain)
    elif args.output == "sarif":
        if not args.out_file:
            logging.error("SARIF output requires --out-file")
        else:
            generate_sarif_report(details, result, args.out_file)
    elif args.output == "junit":
        if not args.out_file:
            logging.error("JUnit output requires --out-file")
        else:
            generate_junit_report(details, result, args.out_file)

    # === Baseline/Exit Codes ===
    summary = result.get("summary", {})
    
    # 1) Quotas
    errors = []
    if summary.get("Critical",0) > args.max_critical: errors.append(f"Critical({summary['Critical']} > {args.max_critical})")
    if summary.get("High",0) > args.max_high: errors.append(f"High({summary['High']} > {args.max_high})")
    if summary.get("Medium",0) > args.max_medium: errors.append(f"Medium({summary['Medium']} > {args.max_medium})")
    if summary.get("Low",0) > args.max_low: errors.append(f"Low({summary['Low']} > {args.max_low})")
    
    if errors and args.fail_on == "none":
        logging.error(f"Quota exceeded: {', '.join(errors)}")
        sys.exit(1)

    # 2) Legacy threshold
    sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    # check if any finding >= threshold
    if args.fail_on != "none":
        threshold_val = sev_rank.get(args.fail_on.title(), 5)
        max_found = 0
        if summary.get("Critical") > 0: max_found = 4
        elif summary.get("High") > 0: max_found = 3
        elif summary.get("Medium") > 0: max_found = 2
        elif summary.get("Low") > 0: max_found = 1
        
        if max_found >= threshold_val:
            logging.error(f"Failure threshold '{args.fail_on}' reached (found severity level {max_found}).")
            sys.exit(1)

    # 3) Baseline Regression
    if args.baseline:
        base_scores = load_baseline(args.baseline) # {fp: score}
        worsened = 0
        new_issues = 0
        
        current_findings = []
        for ep_data in result.get("endpoints", {}).values():
            current_findings.extend(ep_data.get("vulnerabilities", []))
            
        for v in current_findings:
            fp = v["fingerprint"]
            s_score = v["severity_score"]
            old_score = base_scores.get(fp)
            if old_score is None:
                new_issues += 1
            elif s_score > old_score:
                worsened += 1
        
        if worsened > 0:
            logging.error(f"Baseline regression: {worsened} issues have worsened severity.")
            sys.exit(1)
        if new_issues > 0:
            logging.warning(f"Baseline comparison: {new_issues} new issues found.")

if __name__ == "__main__":
    main()
