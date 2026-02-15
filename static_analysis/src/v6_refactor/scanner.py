# -*- coding: utf-8 -*-
import hashlib
import json
import logging
import re
from typing import Dict, Any, List, Set, Tuple, Optional
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import CONFIG, SEVERITY_SCORES
from .models import OasDetails
from .utils import reset_caches
from .helpers import is_suppressed, _endpoint_method_path, _derive_op_pointer
from .rules import RULE_FUNCTIONS, VULNERABILITY_MAP, assign_severity

# View class for single endpoint analysis
class _DetailsView(OasDetails):
    def __init__(self, spec: Dict[str, Any], endpoint: Dict[str, Any]):
        super().__init__(spec)
        self._single = [endpoint]
    @property
    def endpoints(self) -> List[Dict[str, Any]]:
        return self._single

def compute_fingerprint(check_key: str, detail: Dict[str, Any]) -> str:
    parts = [
        check_key,
        str(detail.get("endpoint","")),
        str(detail.get("schema","")),
        str(detail.get("field","")),
        str(detail.get("parameter","")),
        str(detail.get("header",""))
    ]
    base = "|".join(parts)
    return hashlib.sha1(base.encode("utf-8")).hexdigest()

def analyze_spec(details: OasDetails, explain: bool=False) -> Dict[str, Any]:
    findings = defaultdict(lambda: {"vulnerabilities": []})
    vuln_id_counter = 1

    summary_raw = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    summary_norm = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    seen_fps: Set[str] = set()

    all_rules = list(RULE_FUNCTIONS.items())
    for check_key, check_fn in all_rules:
        if check_key in CONFIG.get("disable_rules", set()):
            logging.debug(f"Rule disabled via config/policy pack: {check_key}")
            continue
        if check_key not in VULNERABILITY_MAP:
            logging.warning(f"Skipping rule '{check_key}' because metadata is missing in VULNERABILITY_MAP.")
            continue

        meta = VULNERABILITY_MAP[check_key]

        # reset caches between rules so memory doesn't balloon (safe if helper exists)
        try:
            reset_caches()
        except NameError:
            pass

        # Decide threaded vs single run
        parallel_ok = CONFIG.get("parallel_checks", True) and getattr(check_fn, "parallel_safe", False)
        thread_count = int(CONFIG.get("threads", 8))

        if parallel_ok and thread_count > 1:
            def _run_on_ep(ep: Dict[str, Any]) -> List[Dict[str, Any]]:
                dv = _DetailsView(details.spec(), ep)
                try:
                    return check_fn(dv) or []
                except Exception as e:
                    logging.debug(f"{check_key} failed on {ep.get('path')}: {e}")
                    return []
            with ThreadPoolExecutor(max_workers=thread_count) as pool:
                futures = [pool.submit(_run_on_ep, ep) for ep in details.endpoints]
                results_lists: List[List[Dict[str, Any]]] = []
                for fut in as_completed(futures):
                    results_lists.append(fut.result() or [])
                results = [item for sub in results_lists for item in sub]
        else:
            results = check_fn(details) or []

        for detail in results:
            # ensure json_pointer
            jp = detail.get("json_pointer")
            if not jp:
                # derive from endpoint if available
                ep = detail.get("endpoint", "")
                if " " in ep:
                    m, p = ep.split(" ", 1)
                    jp = _derive_op_pointer(m, p)
                else:
                    jp = "/"

            # suppression check
            suppressed, s_info = is_suppressed(details, jp, check_key)
            if suppressed and not explain:
                # drop if not in explain mode
                continue

            norm_sev = assign_severity(check_key, detail)
            original_sev = meta.get("severity", norm_sev)
            fp = compute_fingerprint(check_key, detail)
            if fp in seen_fps:
                continue
            seen_fps.add(fp)

            entry = {
                "id": f"{meta['owasp_api_top_10'].split(':')[0]}-{vuln_id_counter:03}",
                "rule_key": check_key,
                "name": meta["name"],
                "owasp_ref": meta["owasp_api_top_10"],
                "severity": norm_sev,
                "severity_original": original_sev,
                "severity_score": SEVERITY_SCORES.get(norm_sev, 1),
                "fingerprint": fp,
                "details": {**detail, "json_pointer": jp},
                "recommendation": meta["recommendation"],
                "policy": {
                    "profile": CONFIG.get("profile", "APEX Default"),
                    "blocking": norm_sev in {"High","Critical"},
                    "suppressed": suppressed
                }
            }
            if explain:
                entry["evidence"] = detail.get("evidence", {})
                if suppressed:
                    entry["suppression"] = s_info

            if original_sev != norm_sev:
                entry["severity_policy_note"] = "Severity normalized by APEX policy."

            endpoint = detail.get("endpoint", "global")
            findings[endpoint]["vulnerabilities"].append(entry)

            summary_raw[original_sev] = summary_raw.get(original_sev, 0) + 1
            summary_norm[norm_sev] += 1
            vuln_id_counter += 1

    followups = build_dynamic_followups(details, findings)

    return {
        "endpoints": findings,
        "summary_raw": {**summary_raw, "total": sum(summary_raw.values())},
        "summary": {**summary_norm, "total": sum(summary_norm.values())},
        "dynamic_followups": followups
    }

class NDJSONWriter:
    def __init__(self, path: str):
        self.path = path
        self.fh = open(path, "w", encoding="utf-8")
        self.summary = {"Critical":0,"High":0,"Medium":0,"Low":0}
        self.total = 0
    def emit(self, v: Dict[str, Any]):
        self.fh.write(json.dumps(v, ensure_ascii=False) + "\n")
        self.fh.flush()
        sev = v.get("severity","Low")
        if sev in self.summary: self.summary[sev] += 1
        self.total += 1
    def close(self):
        self.fh.close()

def analyze_spec_incremental(details: OasDetails, writer: NDJSONWriter, explain: bool=False, threads: int=8):
    vuln_id_counter = 1
    all_rules = list(RULE_FUNCTIONS.items())

    for check_key, check_fn in all_rules:
        if check_key in CONFIG.get("disable_rules", set()):
            continue
        if check_key not in VULNERABILITY_MAP:
            continue
        meta = VULNERABILITY_MAP[check_key]

        # reset caches to keep memory bounded across rules
        reset_caches()

        # decide parallelization
        if CONFIG.get("parallel_checks") and getattr(check_fn, "parallel_safe", False) and threads > 1:
            def _run_on_ep(ep):
                dv = _DetailsView(details.spec(), ep)
                try:
                    return check_fn(dv)
                except Exception as e:
                    logging.debug(f"{check_key} failed on {ep.get('path')}: {e}")
                    return []
            with ThreadPoolExecutor(max_workers=threads) as pool:
                futures = [pool.submit(_run_on_ep, ep) for ep in details.endpoints]
                results_lists = []
                for fut in as_completed(futures):
                    results_lists.append(fut.result() or [])
                results = [item for sub in results_lists for item in sub]
        else:
            results = check_fn(details)

        for detail in results:
            # pointer derive + suppression, same semantics as analyze_spec
            jp = detail.get("json_pointer")
            if not jp:
                ep = detail.get("endpoint","")
                if " " in ep:
                    m,p = ep.split(" ",1)
                    jp = _derive_op_pointer(m,p)
                else:
                    jp = "/"
            suppressed, s_info = is_suppressed(details, jp, check_key)
            if suppressed and not explain:
                continue

            norm_sev = assign_severity(check_key, detail)
            original_sev = meta.get("severity", norm_sev)
            fp = compute_fingerprint(check_key, detail)

            entry = {
                "id": f"{meta['owasp_api_top_10'].split(':')[0]}-{vuln_id_counter:03}",
                "rule_key": check_key,
                "name": meta["name"],
                "owasp_ref": meta["owasp_api_top_10"],
                "severity": norm_sev,
                "severity_original": original_sev,
                "severity_score": SEVERITY_SCORES.get(norm_sev, 1),
                "fingerprint": fp,
                "details": {**detail, "json_pointer": jp},
                "recommendation": meta["recommendation"],
                "policy": {
                    "profile": CONFIG.get("profile","default"),
                    "blocking": norm_sev in {"High","Critical"},
                    "suppressed": suppressed
                }
            }
            if explain:
                entry["evidence"] = detail.get("evidence", {})
                if suppressed:
                    entry["suppression"] = s_info

            writer.emit(entry)
            vuln_id_counter += 1

def build_dynamic_followups(details: OasDetails, findings_by_ep: Dict[str, Any]) -> List[Dict[str, Any]]:
    tasks: List[Dict[str, Any]] = []
    servers = [s for s in details.get_servers() if isinstance(s, dict)]
    base_urls = [s.get('url') for s in servers if isinstance(s.get('url'), str)]

    for ep, data in findings_by_ep.items():
        for v in data["vulnerabilities"]:
            if v.get("rule_key") == "check_inventory_deprecated":
                method, path = _endpoint_method_path(v["details"])
                tasks.append({
                    "id": f"DFU-{len(tasks)+1:03}",
                    "category": "Deprecated",
                    "priority": "Low",
                    "title": f"Probe deprecated {method} {path}",
                    "suggested_requests": [
                        {"method": method or "GET", "url_template": f"<server>{path}", "notes": "Expect 404/410 or redirect; flag if 200/204."}
                    ],
                    "related_findings": [v["id"]]
                })

    has_versioning_issue = any(
        v.get("rule_key") == "check_inventory_versioning"
        for data in findings_by_ep.values()
        for v in data["vulnerabilities"]
    )
    if has_versioning_issue:
        unique_paths = sorted({ep_path for ep_path in (e['path'] for e in details.endpoints)})
        guess_versions = ["v1","v2","v3"]
        for p in unique_paths:
            m = re.match(r'^/v(\d+)(/.*|$)', p, re.IGNORECASE)
            variants = []
            if m:
                cur = int(m.group(1))
                for n in [cur-1, cur+1]:
                    if n >= 0:
                        variants.append(re.sub(r'^/v\d+', f"/v{n}", p, flags=re.IGNORECASE))
            else:
                for gv in guess_versions:
                    variants.append(f"/{gv}{p if p.startswith('/') else '/'+p}")
            if variants:
                tasks.append({
                    "id": f"DFU-{len(tasks)+1:03}",
                    "category": "Shadow Versions",
                    "priority": "Medium",
                    "title": f"Probe shadow versions for '{p}'",
                    "suggested_requests": [{"method": "GET", "url_template": f"<server>{v}", "notes": "Look for 200/302; compare auth requirements."} for v in variants],
                    "related_findings": []
                })

    ssrf_related_ids = []
    for ep, data in findings_by_ep.items():
        for v in data["vulnerabilities"]:
            if v.get("rule_key") in {"check_ssrf_query_params","check_ssrf_request_bodies","check_ssrf_server_variables","check_ssrf_hardening_fields"}:
                ssrf_related_ids.append(v["id"])
    if ssrf_related_ids:
        tasks.append({
            "id": f"DFU-{len(tasks)+1:03}",
            "category": "SSRF",
            "priority": "Medium",
            "title": "SSRF probes for URL inputs (authorized test only)",
            "suggested_requests": [
                {"method": "POST/GET", "url_template": "<target>", "notes": "Try 127.0.0.1, ::1, 169.254.169.254, file:// (if accepted)."},
                {"method": "POST/GET", "url_template": "<target>", "notes": "Test private IP ranges and disallowed domains; expect rejection."}
            ],
            "related_findings": ssrf_related_ids
        })

    has_mixed_servers = any(
        v.get("rule_key") == "check_inventory_mixed_servers"
        for data in findings_by_ep.values()
        for v in data["vulnerabilities"]
    )
    if has_mixed_servers and base_urls:
        tasks.append({
            "id": f"DFU-{len(tasks)+1:03}",
            "category": "Inventory",
            "priority": "Low",
            "title": "Probe mixed servers for drift",
            "suggested_requests": [{"method": "GET", "url_template": f"{u}/__health or /version", "notes": "Confirm environment labeling & auth."} for u in base_urls],
            "related_findings": []
        })
    return tasks
