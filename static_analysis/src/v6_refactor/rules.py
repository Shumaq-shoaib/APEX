# -*- coding: utf-8 -*-
import re
import os
import yaml
import logging
import importlib.util
from typing import Dict, Any, List, Set, Tuple, Callable
from collections import defaultdict

from .config import CONFIG
from .models import OasDetails
from .utils import (
    _run_plugin_sandboxed, _verify_sidecar_sig, _semver_ok, _verify_pack_signature,
    reset_caches, _resolve_ref, _walk_properties, _iter_request_body_schemas,
    _merge_allOf
)
from .helpers import (
    _endpoint_method_path, _extract_path_params_from_path, _is_sensitive_id_name,
    _collect_operation_scopes, _extract_vendor_scopes, _is_vendor_sensitive,
    _is_keyword_sensitive, _looks_broad, _has_privileged, _resource_guess,
    _verb_implies_privileged, _scope_match, _is_unconstrained_object,
    _is_urlish_field, _has_allowlist_language, _is_https_only_pattern,
    _host_like_name, RFC1918_OR_META, _iter_uri_like_fields,
    PRIVATE_HOST_RE, _endpoint_tags, _rfc1918_or_meta_ip, _iter_operation_examples
)

RuleFn = Callable[[OasDetails], List[Dict[str, Any]]]

VULNERABILITY_MAP: Dict[str, Dict[str, Any]] = {
    'check_broken_object_level_authorization': {'owasp_api_top_10':'API1:2023','name':'Broken Object Level Authorization','severity':'Critical','prefix':'BOLA Risk','recommendation':'Implement object-level authorization checks.'},
    'check_broken_authentication': {'owasp_api_top_10':'API2:2023','name':'Broken Authentication','severity':'Critical','prefix':'Broken Authentication','recommendation':'Use OAuth2/OIDC; avoid Basic/Digest; set bearerFormat; define OAuth2 scopes.'},
    'check_sensitive_id_security': {'owasp_api_top_10':'API1:2023','name':'Sensitive ID Without Security','severity':'Critical','prefix':'BOLA Risk','recommendation':'Protect ID paths with security.'},
    'check_bopla_property_level_exposure': {'owasp_api_top_10':'API3:2023','name':'Broken Object Property Level Authorization','severity':'Medium','prefix':'Property-Level Exposure','recommendation':'Enforce field-level authorization and scoped models.'},
    'check_schema_sensitive_fields_exposure': {'owasp_api_top_10':'INFO','name':'Schema Sensitive Fields Exposure','severity':'Informational','prefix':'Schema Sensitive','recommendation':'Review schema definitions; informational unless corroborated.'},
    'check_doc_hint_rate_limit_headers': {'owasp_api_top_10':'HINT','name':'Documentation Hint: Rate-Limit Headers','severity':'Informational','prefix':'Documentation Hint','recommendation':'Document rate limit headers; enforce at runtime.'},
    'check_doc_hint_security_headers': {'owasp_api_top_10':'HINT','name':'Documentation Hint: Security Headers','severity':'Informational','prefix':'Documentation Hint','recommendation':'Document common security headers; verify dynamically.'},
    'check_security_misconfiguration': {'owasp_api_top_10':'API8:2023','name':'Security Misconfiguration','severity':'Low','prefix':'Security Misconfiguration','recommendation':'Disable insecure HTTP verbs (e.g., TRACE).'},
    'check_improper_inventory': {'owasp_api_top_10':'API9:2023','name':'Improper Inventory Management','severity':'Low','prefix':'Improper Inventory','recommendation':'Ensure endpoints have descriptions and are tracked.'},
    'check_unsafe_consumption': {'owasp_api_top_10':'API10:2023','name':'Unsafe Consumption of APIs','severity':'Low','prefix':'Unsafe Consumption','recommendation':'Use HTTPS for servers.'},
    'check_ssrf_query_params': {'owasp_api_top_10':'API7:2023','name':'SSRF Risk (Query/Path Params)','severity':'Medium','prefix':'SSRF Risk','recommendation':'Restrict URL params with enum/pattern.'},
    'check_ssrf_request_bodies': {'owasp_api_top_10':'API7:2023','name':'SSRF Risk (Request Body)','severity':'Medium','prefix':'SSRF Risk','recommendation':'Restrict URL fields in bodies with enum/pattern.'},
    'check_ssrf_server_variables': {'owasp_api_top_10':'API7:2023','name':'Server Variable Not Enum-Restricted','severity':'Medium','prefix':'SSRF/Route Risk','recommendation':'Restrict server URL variables via enum.'},
    'check_inventory_deprecated': {'owasp_api_top_10':'API9:2023','name':'Deprecated Operation Present','severity':'Low','prefix':'Inventory','recommendation':'Retire deprecated endpoints.'},
    'check_inventory_versioning': {'owasp_api_top_10':'API9:2023','name':'Versioning Inconsistency','severity':'Low','prefix':'Inventory','recommendation':'Standardize path versioning.'},
    'check_inventory_mixed_servers': {'owasp_api_top_10':'API9:2023','name':'Mixed Server Base URLs','severity':'Low','prefix':'Inventory','recommendation':'Avoid mixing env base URLs in one spec.'},
    'check_broken_function_level_authorization': {'owasp_api_top_10':'API5:2023','name':'Broken Function Level Authorization','severity':'Medium','prefix':'Authorization','recommendation':'Ensure consistent security across operations sharing a path; require auth on state-changing methods and enforce role/permission checks.'},
    'check_auth_consistency': {'owasp_api_top_10':'API5:2023','name':'Auth Consistency','severity':'Medium','prefix':'Authorization','recommendation':'Do not disable auth on state-changing operations; model 401/403 when security is required.'},
    'check_ssrf_hardening_fields': {'owasp_api_top_10':'API7:2023','name':'SSRF Hardening (URL Inputs)','severity':'High','prefix':'SSRF','recommendation':'Enforce https-only, host allow-list, and deny-list for URL inputs.'},
    'check_unsafe_get_side_effects': {'owasp_api_top_10':'API4:2023','name':'Unsafe GET (Side Effects)','severity':'Medium','prefix':'HTTP Semantics','recommendation':'Ensure GET is safe/idempotent; move side-effecting actions to POST/PUT/PATCH.'},
    'check_internal_reference_leakage': {'owasp_api_top_10':'API9:2023','name':'Internal Reference/Env Leakage','severity':'Medium','prefix':'Information Exposure','recommendation':'Avoid leaking internal hosts/IPs in examples; sanitize example data.'},
}

RULE_FUNCTIONS: Dict[str, RuleFn] = {}

def assign_severity(check_key: str, detail: Dict[str, Any]) -> str:
    # 1) Base severity (existing policy first)
    if check_key in CONFIG.get("override_severity", {}):
        base = CONFIG["override_severity"][check_key]
    else:
        desc = (detail.get("description") or "").lower()
        # CRITICAL escalations
        if check_key in ("check_sensitive_id_security",):
            base = "Critical"
        elif check_key == "check_broken_authentication" and (
            "no security schemes" in desc or "weak http auth scheme 'basic'" in desc or "weak http auth scheme 'digest'" in desc):
            base = "Critical"
        elif check_key == "check_auth_consistency" and "disables auth" in desc:
            base = "Critical"
        # HIGH
        elif check_key in ("check_ssrf_hardening_fields",):
            base = "High"
        elif check_key == "check_broken_authentication" and (
            "defines no flows" in desc or "none with scopes" in desc or "without declaring required scopes" in desc):
            base = "High"
        elif check_key == "check_bopla_property_level_exposure" and (
            "requires scopes" in desc or "publicly expose internal/sensitive" in desc or "allowing both privileged and broad scopes" in desc):
            base = "High"
        elif check_key == "check_unsafe_consumption":
            base = "High"
        # MEDIUM
        elif check_key in ("check_ssrf_query_params","check_ssrf_request_bodies","check_ssrf_server_variables",
                           "check_unsafe_get_side_effects","check_internal_reference_leakage","check_auth_consistency"):
            base = "Medium"
        elif check_key == "check_security_misconfiguration" and "trace" in desc:
            base = "Medium"
        # LOW
        elif check_key in ("check_doc_hint_rate_limit_headers","check_doc_hint_security_headers",
                           "check_schema_sensitive_fields_exposure","check_improper_inventory",
                           "check_inventory_deprecated","check_inventory_versioning","check_inventory_mixed_servers"):
            base = "Low"
        elif check_key == "check_broken_authentication" and ("bearerformat" in desc or "bearer scheme" in desc):
            base = "Low"
        else:
            base = VULNERABILITY_MAP.get(check_key, {}).get("severity", "Low")

    # 2) Profile adjustments
    profile = CONFIG.get("profile", "default")
    bump = { "Low":1, "Medium":2, "High":3, "Critical":4 }
    inv  = { 1:"Low", 2:"Medium", 3:"High", 4:"Critical" }

    score = bump.get(base, 1)

    if profile in ("production","pci","hipaa"):
        # Production-like: raise network & auth hardening issues
        if check_key in ("check_unsafe_consumption","check_ssrf_hardening_fields","check_auth_consistency"):
            score = min(4, score + 1)
    elif profile == "sandbox":
        # Sandbox: soften doc & inventory hints
        if check_key in ("check_doc_hint_rate_limit_headers","check_doc_hint_security_headers",
                         "check_improper_inventory","check_inventory_mixed_servers"):
            score = max(1, score - 1)

    return inv[score]


# --- Built-in checks ---
def check_broken_object_level_authorization(details: OasDetails) -> List[Dict[str, Any]]:
    findings = []
    for ep in details.endpoints:
        placeholders = _extract_path_params_from_path(ep['path'])
        if placeholders and not ep.get('security'):
            if any(_is_sensitive_id_name(p) for p in placeholders):
                continue
            findings.append({
                "description": f"Endpoint {ep['method']} {ep['path']} missing security for object access.",
                "schema": None, "field": None, "parameter": None, "header": None,
                "endpoint": f"{ep['method']} {ep['path']}",
                "evidence": {"placeholders": placeholders, "security": ep.get('security')}
            })
    return findings

def check_sensitive_id_security(details: OasDetails) -> List[Dict[str, Any]]:
    findings = []
    for ep in details.endpoints:
        placeholders = _extract_path_params_from_path(ep['path'])
        sensitive_ids = [p for p in placeholders if _is_sensitive_id_name(p)]
        if sensitive_ids and not ep.get('security'):
            findings.append({
                "description": (f"Endpoint {ep['method']} {ep['path']} contains sensitive ID parameter(s) "
                                f"{sensitive_ids} but has no global or operation-level security."),
                "schema": None, "field": None, "parameter": ",".join(sensitive_ids), "header": None,
                "endpoint": f"{ep['method']} {ep['path']}",
                "evidence": {"path_params": placeholders, "sensitive_ids": sensitive_ids, "security": ep.get('security')}
            })
    return findings

def check_broken_authentication(d: OasDetails) -> List[Dict[str, Any]]:
    findings = []
    schemes = d.get_security_schemes()

    if not schemes:
        findings.append({
            "description": "No security schemes are defined for the entire API.",
            "schema": None, "field": None, "parameter": None, "header": None,
            "endpoint": "global",
            "evidence": {"securitySchemes": {}}
        })
    else:
        for name, s in schemes.items():
            stype = s.get('type', '').lower()
            if stype == 'http':
                scheme = (s.get('scheme') or '').lower()
                if scheme in {'basic','digest'}:
                    findings.append({
                        "description": f"Weak HTTP auth scheme '{scheme}' in '{name}'. Avoid Basic/Digest; use OAuth2/OIDC or bearer tokens.",
                        "schema": None, "field": None, "parameter": None, "header": None,
                        "endpoint": "global",
                        "evidence": {"schemeName": name, "scheme": s}
                    })
                elif scheme == 'bearer':
                    bfmt = str(s.get('bearerFormat', '')).strip()
                    if not bfmt:
                        findings.append({
                            "description": f"Bearer scheme '{name}' has no bearerFormat (e.g., 'JWT'). Add bearerFormat for clarity and tooling.",
                            "schema": None, "field": None, "parameter": None, "header": None,
                            "endpoint": "global",
                            "evidence": {"schemeName": name, "scheme": s}
                        })
            elif stype == 'oauth2':
                flows = s.get('flows') or {}
                if not isinstance(flows, dict) or not flows:
                    findings.append({
                        "description": f"OAuth2 scheme '{name}' defines no flows. Define at least one flow with scopes.",
                        "schema": None, "field": None, "parameter": None, "header": None,
                        "endpoint": "global",
                        "evidence": {"schemeName": name, "scheme": s}
                    })
                else:
                    has_any_scopes = False
                    for flow_name, flow in flows.items():
                        scopes = flow.get('scopes') or {}
                        if not isinstance(scopes, dict) or not scopes:
                            findings.append({
                                "description": f"OAuth2 scheme '{name}' flow '{flow_name}' defines no scopes. Provide least-privilege scopes.",
                                "schema": None, "field": None, "parameter": None, "header": None,
                                "endpoint": "global",
                                "evidence": {"schemeName": name, "flow": flow_name, "flowDef": flow}
                            })
                        else:
                            has_any_scopes = True
                    if not has_any_scopes:
                        findings.append({
                            "description": f"OAuth2 scheme '{name}' has flows but none with scopes. Define non-empty scopes per flow.",
                            "schema": None, "field": None, "parameter": None, "header": None,
                            "endpoint": "global",
                            "evidence": {"schemeName": name, "scheme": s}
                        })

    for ep in d.endpoints:
        op_sec = ep.get('security')
        if not isinstance(op_sec, list) or not op_sec:
            continue
        for req in op_sec:
            if not isinstance(req, dict):
                continue
            for scheme_name, scope_list in req.items():
                sdef = schemes.get(scheme_name) if isinstance(schemes, dict) else None
                if sdef and str(sdef.get('type','')).lower() == 'oauth2':
                    if scope_list is None or (isinstance(scope_list, list) and len(scope_list) == 0):
                        findings.append({
                            "description": (f"Operation {ep['method']} {ep['path']} uses OAuth2 scheme '{scheme_name}' "
                                            f"without declaring required scopes. Specify least-privilege scopes."),
                            "schema": None, "field": None, "parameter": None, "header": None,
                            "endpoint": f"{ep['method']} {ep['path']}",
                            "evidence": {"operationSecurity": op_sec}
                        })
    return findings

def check_doc_hint_rate_limit_headers(d: OasDetails) -> List[Dict[str, Any]]:
    if not CONFIG.get("enable_doc_hint_rate_limit_headers", True):
        return []
    expected = {'x-rate-limit-limit', 'x-rate-limit-remaining', 'x-rate-limit-reset'}
    by_tag = defaultdict(lambda: {"missing_on": [], "present_headers": set()})

    for e in d.endpoints:
        present = set()
        for r in e.get('responses', {}).values():
            if isinstance(r, dict):
                present |= {h.lower() for h in r.get('headers', {}).keys()}
        if expected.isdisjoint(present):
            for tag in _endpoint_tags(e):
                by_tag[tag]["missing_on"].append(f"{e['method']} {e['path']}")
        else:
            for tag in _endpoint_tags(e):
                by_tag[tag]["present_headers"] |= present

    findings = []
    for tag, agg in by_tag.items():
        if not agg["missing_on"]:
            continue
        findings.append({
            "description": (f"Documentation hint (per tag '{tag}'): declare rate-limit headers "
                            f"({', '.join(sorted(expected))}). {len(agg['missing_on'])} endpoint(s) missing."),
            "schema": None, "field": None, "parameter": None, "header": None,
            "endpoint": f"tag:{tag}",
            "evidence": {"examples": agg["missing_on"][:10]}
        })
    return findings

def check_doc_hint_security_headers(d: OasDetails) -> List[Dict[str, Any]]:
    if not CONFIG.get("enable_doc_hint_security_headers", True):
        return []
    required = set(CONFIG['required_security_headers'])
    by_tag_missing = defaultdict(lambda: {"endpoints": [], "missing_unioned": set()})

    for e in d.endpoints:
        present_all = set()
        for r in e.get('responses', {}).values():
            if isinstance(r, dict):
                present_all |= {h.lower() for h in r.get('headers', {}).keys()}
        missing = required - present_all
        if missing:
            for tag in _endpoint_tags(e):
                by_tag_missing[tag]["endpoints"].append(f"{e['method']} {e['path']}")
                by_tag_missing[tag]["missing_unioned"] |= missing

    findings = []
    for tag, agg in by_tag_missing.items():
        findings.append({
            "description": (f"Documentation hint (per tag '{tag}'): add common security headers in responses "
                            f"(missing in spec: {', '.join(sorted(agg['missing_unioned']))}). "
                            f"{len(agg['endpoints'])} endpoint(s) affected."),
            "schema": None, "field": None, "parameter": None, "header": None,
            "endpoint": f"tag:{tag}",
            "evidence": {"examples": agg["endpoints"][:10]}
        })
    return findings

def check_security_misconfiguration(d: OasDetails) -> List[Dict[str, Any]]:
    findings = []
    for e in d.endpoints:
        if e['method'] == 'TRACE':
            findings.append({
                "description": f"Endpoint {e['method']} {e['path']} enables insecure TRACE method.",
                "schema": None, "field": None, "parameter": None, "header": "TRACE",
                "endpoint": f"{e['method']} {e['path']}",
                "evidence": {"method": e['method'], "path": e['path']}
            })
    return findings

def check_improper_inventory(d: OasDetails) -> List[Dict[str, Any]]:
    findings = []
    for e in d.endpoints:
        if not (e.get('summary') or e.get('description')):
            findings.append({
                "description": f"Endpoint {e['method']} {e['path']} lacks a summary/description.",
                "schema": None, "field": None, "parameter": None, "header": None,
                "endpoint": f"{e['method']} {e['path']}",
                "evidence": {"summary": e.get('summary'), "description": e.get('description')}
            })
    return findings

def check_unsafe_consumption(d: OasDetails) -> List[Dict[str, Any]]:
    findings = []
    for s in d.get_servers():
        if isinstance(s, dict) and str(s.get('url', '')).startswith('http://'):
            findings.append({
                "description": f"Insecure server URL '{s['url']}' defined. Use HTTPS.",
                "schema": None, "field": None, "parameter": None, "header": None,
                "endpoint": "global",
                "evidence": {"server": s}
            })
    return findings

def check_ssrf_query_params(details: OasDetails) -> List[Dict[str, Any]]:
    findings = []
    for ep in details.endpoints:
        for param in ep.get('parameters', []):
            if not isinstance(param, dict):
                continue
            schema = param.get('schema', {})
            if schema and schema.get('type') == 'string' and schema.get('format') in ['uri', 'url']:
                if not ('pattern' in schema or 'enum' in schema):
                    findings.append({
                        "description": f"Endpoint {ep['method']} {ep['path']} has URL parameter '{param.get('name')}' without enum/pattern allow-list.",
                        "schema": None, "field": None, "parameter": param.get('name'), "header": None,
                        "endpoint": f"{ep['method']} {ep['path']}",
                        "evidence": {"parameter": param}
                    })
    return findings

def check_ssrf_request_bodies(details: OasDetails) -> List[Dict[str, Any]]:
    spec = details.spec()
    findings = []
    for ep in details.endpoints:
        for sname, sdef in _iter_request_body_schemas(spec, ep.get('requestBody')):
            for prop_path, prop_def in _walk_properties(spec, sdef, _seen_nodes=set(), _seen_refs=set()):
                pname = prop_path.split(".")[-1].replace("[]", "")
                desc = prop_def.get("description") or ""
                if _is_urlish_field(pname, prop_def, desc):
                    restricted = ('enum' in prop_def) or ('pattern' in prop_def) or _has_allowlist_language(desc)
                    if not restricted:
                        findings.append({
                            "description": (f"Endpoint {ep['method']} {ep['path']} request body field '{prop_path}' "
                                            "looks like a URL but has no enum/pattern or allow-list mention in description."),
                            "schema": sname, "field": prop_path, "parameter": None, "header": None,
                            "endpoint": f"{ep['method']} {ep['path']}",
                            "evidence": {"schema": sname, "field_def": prop_def}
                        })
    return findings

def check_ssrf_server_variables(details: OasDetails) -> List[Dict[str, Any]]:
    findings = []
    servers = details.get_servers()
    for s in servers:
        if not isinstance(s, dict):
            continue
        url_tmpl = str(s.get('url',''))
        vars_def = s.get('variables', {}) or {}
        if not url_tmpl or not isinstance(vars_def, dict):
            continue

        # host portion (to detect {env} in host)
        host_part = ""
        m = re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://([^/]+)', url_tmpl)
        if m:
            host_part = m.group(1)

        vars_in_url = re.findall(r'\{([^}/]+)\}', url_tmpl)
        for vn in vars_in_url:
            vdef = vars_def.get(vn, {}) or {}
            desc = " ".join([str(vdef.get("description","")), str(s.get("description",""))]).strip()
            enum = vdef.get("enum")
            default = vdef.get("default")
            examples = vdef.get("examples") or []
            values = []
            if enum and isinstance(enum, list): values.extend(enum)
            if default is not None: values.append(default)
            if isinstance(examples, list): values.extend(examples)

            in_host = ("{" + vn + "}") in host_part
            has_enum = isinstance(enum, list) and len(enum) > 0
            allow_text = _has_allowlist_language(desc)

            # (1) variable in host without enum
            if in_host and not has_enum:
                findings.append({
                    "description": (f"Server URL '{url_tmpl}' uses host variable '{vn}' without enum restriction. "
                                    f"Host can drift to unsafe targets."),
                    "schema": None, "field": None, "parameter": vn, "header": None,
                    "endpoint": "global",
                    "evidence": {"server_url": url_tmpl, "variable": vn, "variable_def": vdef}
                })

            # (2) unsafe values in defaults/enums/examples
            for val in values:
                sval = str(val)
                if sval.startswith("http://") or _rfc1918_or_meta_ip(sval):
                    findings.append({
                        "description": (f"Server variable '{vn}' in '{url_tmpl}' has unsafe value '{sval}' "
                                        f"(plaintext or private/metadata IP)."),
                        "schema": None, "field": None, "parameter": vn, "header": None,
                        "endpoint": "global",
                        "evidence": {"value": sval, "variable": vn}
                    })

            # (3) no enum and no allow-list language anywhere
            if not has_enum and not allow_text:
                findings.append({
                    "description": (f"Server URL '{url_tmpl}' uses variable '{vn}' without enum/allow-list. "
                                    f"Document and restrict allowed values."),
                    "schema": None, "field": None, "parameter": vn, "header": None,
                    "endpoint": "global",
                    "evidence": {"variable": vn, "variable_def": vdef}
                })
    return findings

def check_inventory_deprecated(details: OasDetails) -> List[Dict[str, Any]]:
    findings = []
    for ep in details.endpoints:
        if ep.get('deprecated'):
            findings.append({
                "description": f"Operation {ep['method']} {ep['path']} is marked deprecated.",
                "schema": None, "field": None, "parameter": None, "header": None,
                "endpoint": f"{ep['method']} {ep['path']}",
                "evidence": {"deprecated": True}
            })
    return findings

def check_inventory_versioning(details: OasDetails) -> List[Dict[str, Any]]:
    findings = []
    paths = [e['path'] for e in details.endpoints]
    versioned = set(); unversioned = set(); versions_seen = set()
    for p in set(paths):
        m = re.match(r'^/v(\d+)(/|$)', p, re.IGNORECASE)
        if m:
            versions_seen.add(m.group(1)); versioned.add(p)
        else:
            unversioned.add(p)
    if versioned and unversioned:
        findings.append({
            "description": "Spec mixes versioned and unversioned paths. Standardize versioning (e.g., /v{major}/...).",
            "schema": None, "field": None, "parameter": None, "header": None,
            "endpoint": "global",
            "evidence": {"versioned_paths": len(versioned), "unversioned_paths": len(unversioned)}
        })
    if len(versions_seen) > 1:
        findings.append({
            "description": f"Multiple major versions present in paths: v{', v'.join(sorted(versions_seen))}. Ensure old versions are retired.",
            "schema": None, "field": None, "parameter": None, "header": None,
            "endpoint": "global",
            "evidence": {"versions": sorted(versions_seen)}
        })
    return findings

def check_inventory_mixed_servers(details: OasDetails) -> List[Dict[str, Any]]:
    findings = []
    servers = [s for s in details.get_servers() if isinstance(s, dict)]
    if len(servers) <= 1:
        return findings
    schemes = set(); hosts = set()
    for s in servers:
        url = str(s.get('url',''))
        m = re.match(r'^([a-zA-Z][a-zA-Z0-9+\-.]*?)://([^/]+)', url)
        if not m:
            continue
        schemes.add(m.group(1).lower()); hosts.add(m.group(2).lower())
    if len(hosts) > 1 or len(schemes) > 1:
        findings.append({
            "description": f"Spec lists mixed server bases (schemes: {sorted(schemes)}, hosts: {sorted(hosts)}). Separate envs or clearly label them.",
            "schema": None, "field": None, "parameter": None, "header": None,
            "endpoint": "global",
            "evidence": {"schemes": sorted(schemes), "hosts": sorted(hosts)}
        })
    return findings

def check_schema_sensitive_fields_exposure(details: OasDetails) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for schema_name in details.get_schemas().keys():
        root = details.get_schemas().get(schema_name, {})
        for prop_path, prop_def in _walk_properties(details.spec(), root, base=schema_name, _seen_nodes=set(), _seen_refs=set()):
            pname = prop_path.split(".")[-1].replace("[]", "")
            if _is_keyword_sensitive(pname) or _is_vendor_sensitive(prop_def):
                findings.append({
                    "description": f"Sensitive-looking field '{prop_path}' present in schema '{schema_name}'.",
                    "schema": schema_name, "field": prop_path, "parameter": None, "header": None,
                    "endpoint": "global",
                    "evidence": {"schema": schema_name, "field_def": prop_def}
                })
    return findings

def check_bopla_property_level_exposure(details: OasDetails) -> List[Dict[str, Any]]:
    spec = details.spec()
    findings: List[Dict[str, Any]] = []
    for ep in details.endpoints:
        op_scopes = _collect_operation_scopes(ep.get('security'))
        responses = ep.get('responses', {}) or {}
        # consider only 2xx as "returned"
        for code, r in responses.items():
            if not str(code).startswith("2") or not isinstance(r, dict):
                continue
            content = r.get('content', {}) or {}
            for mt, media in content.items():
                if not any(str(mt).lower().startswith(x) for x in CONFIG["json_media_types"]):
                    continue
                schema = media.get('schema')
                if not schema:
                    continue
                if isinstance(schema, dict) and '$ref' in schema:
                    sname, sdef = _resolve_ref(spec, schema['$ref'])
                else:
                    sname, sdef = "<inline>", schema
                if not isinstance(sdef, dict):
                    continue
                # merge allOf (to union required)
                if 'allOf' in sdef:
                    sdef = _merge_allOf(sdef, spec, set())

                required = set(sdef.get("required", []) or [])
                # 1) sensitive required fields (unavoidably returned)
                for prop_path, prop_def in _walk_properties(spec, sdef, _seen_nodes=set(), _seen_refs=set()):
                    pname = prop_path.split(".")[-1].replace("[]","")
                    keyword_sensitive = _is_keyword_sensitive(pname)
                    vendor_sensitive = _is_vendor_sensitive(prop_def)
                    if pname in required and (keyword_sensitive or vendor_sensitive):
                        findings.append({
                            "description": (f"{ep['method']} {ep['path']} returns **required** sensitive field '{prop_path}'. "
                                            "Enforce field-level authorization or split response models."),
                            "schema": sname, "field": prop_path, "parameter": None, "header": None,
                            "endpoint": f"{ep['method']} {ep['path']}",
                            "evidence": {"required": sorted(required), "sensitive_field": pname}
                        })

                # 2) unconstrained additionalProperties with sensitive-looking names
                if _is_unconstrained_object(sdef):
                    findings.append({
                        "description": (f"{ep['method']} {ep['path']} returns object with unconstrained additionalProperties. "
                                        "Sensitive data may leak via dynamic keys. Constrain with schema or patternProperties."),
                        "schema": sname, "field": "<additionalProperties>", "parameter": None, "header": None,
                        "endpoint": f"{ep['method']} {ep['path']}",
                        "evidence": {"schema": sname}
                    })

                # 3) vendor-scoped fields vs op scopes (keep your previous logic)
                for prop_path, prop_def in _walk_properties(spec, sdef, _seen_nodes=set(), _seen_refs=set()):
                    pname = prop_path.split(".")[-1].replace("[]","")
                    vendor_scopes = _extract_vendor_scopes(prop_def)
                    if vendor_scopes:
                        if (not op_scopes) or (not vendor_scopes.issubset(op_scopes)) or _looks_broad(op_scopes):
                            findings.append({
                                "description": (f"{ep['method']} {ep['path']} may expose restricted field '{prop_path}' "
                                                f"(requires scopes {sorted(vendor_scopes)}), but operation scopes are "
                                                f"{sorted(op_scopes) or ['<none>']}."),
                                "schema": sname, "field": prop_path, "parameter": None, "header": None,
                                "endpoint": f"{ep['method']} {ep['path']}",
                                "evidence": {"operation_scopes": sorted(op_scopes), "vendor_scopes": sorted(vendor_scopes)}
                            })
    return findings

def check_broken_function_level_authorization(d: OasDetails) -> List[Dict[str, Any]]:
    by_path = defaultdict(list)
    for e in d.endpoints:
        by_path[e['path']].append((e['method'], bool(e.get('security'))))
    findings = []
    for p, methods in by_path.items():
        secured = [m for m, s in methods if s]; unsecured = [m for m, s in methods if not s]
        if secured and unsecured:
            findings.append({
                "description": f"Path '{p}' has inconsistent security. Secured: {secured}, Unsecured: {unsecured}.",
                "schema": None, "field": None, "parameter": None, "header": None,
                "endpoint": p,
                "evidence": {"secured": secured, "unsecured": unsecured}
            })
    return findings

def check_auth_consistency(details: OasDetails) -> List[Dict[str, Any]]:
    findings = []
    schemes = details.get_security_schemes()

    for ep in details.endpoints:
        m = ep['method']; path = ep['path']
        raw_sec = ep.get('op_security_raw', None)
        has_explicit_none = isinstance(raw_sec, list) and len(raw_sec) == 0  # security:[]
        resps = ep.get('responses', {}) or {}
        codes = {str(c) for c in resps.keys()}
        sec_eff = ep.get('security')
        scopes = _collect_operation_scopes(sec_eff)
        tags = ep.get('tags', []) or []
        resource = _resource_guess(tags, path)
        implied = _verb_implies_privileged(m, ep.get('summary',''), ep.get('description',''))

        # Rule A: state-changing with explicit security disabled
        if ({"write","delete","admin"} & implied) and has_explicit_none:
            findings.append({
                "description": f"Operation {m} {path} implies privileged action ({sorted(implied)}) but disables auth (security: []).",
                "schema": None, "field": None, "parameter": None, "header": None,
                "endpoint": f"{m} {path}",
                "evidence": {"op_security_raw": raw_sec, "implied_privilege": sorted(implied)}
            })

        # Rule B: security present but 401/403 not modeled
        if sec_eff:
            missing = [c for c in ("401","403") if c not in codes]
            if missing:
                findings.append({
                    "description": f"{m} {path} uses security but does not declare {', '.join(missing)} response(s).",
                    "schema": None, "field": None, "parameter": None, "header": None,
                    "endpoint": f"{m} {path}",
                    "evidence": {"responses_modeled": sorted(codes)}
                })

        # Rule C: implied privilege but scopes don't reflect required verbs
        if implied and sec_eff:
            if not _scope_match(implied, scopes, resource):
                findings.append({
                    "description": (f"{m} {path} implies {sorted(implied)} on '{resource}', but declared scopes "
                                    f"{sorted(scopes) or ['<none>']} do not cover it (expect '{resource}:write' or 'admin:*')."),
                    "schema": None, "field": None, "parameter": None, "header": None,
                    "endpoint": f"{m} {path}",
                    "evidence": {"implied": sorted(implied), "scopes": sorted(scopes), "resource": resource}
                })

        # Rule D: clearly sensitive path but no global/operation security
        placeholders = _extract_path_params_from_path(path)
        pii_hint = any(_is_sensitive_id_name(p) for p in placeholders)
        if pii_hint and not sec_eff:
            findings.append({
                "description": (f"{m} {path} references sensitive identifiers {placeholders} but has no security. "
                                "Protect with auth and least-privilege scopes."),
                "schema": None, "field": None, "parameter": None, "header": None,
                "endpoint": f"{m} {path}",
                "evidence": {"path_params": placeholders}
            })

    return findings

def check_ssrf_hardening_fields(details: OasDetails) -> List[Dict[str, Any]]:
    spec = details.spec()
    findings: List[Dict[str, Any]] = []

    def _patterns_ok(s: Dict[str, Any], desc: str) -> Tuple[bool, Dict[str, Any]]:
        patt = s.get("pattern")
        patt_list = []
        # vendor ext multi-patterns (logical AND)
        for k in ("x-apex-patterns", "x_patterns", "x-patterns"):
            v = s.get(k)
            if isinstance(v, list):
                patt_list.extend([str(x) for x in v if isinstance(x, (str,int,float))])
        if isinstance(patt, str) and patt.strip():
            patt_list.append(patt.strip())

        enum = s.get("enum")
        https_only = False
        if enum and isinstance(enum, list):
            https_only = all(str(v).lower().startswith(("https://","wss://")) for v in enum)
        elif patt_list:
            https_only = all(_is_https_only_pattern(p) for p in patt_list)

        # allow-list mention by enum or doc
        allowish = bool(enum) or _has_allowlist_language(desc)

        # deny-list for localhost/private/meta
        denyish = False
        if patt_list:
            denyish = any(RFC1918_OR_META.search(p or "") for p in patt_list)
        if not denyish and desc:
            dl = desc.lower()
            denyish = any(x in dl for x in ("deny","block","disallow","private ip","localhost","169.254.169.254","127.0.0.1"))

        return (https_only and allowish and denyish, {
            "enum": enum, "patterns": patt_list, "https_only": https_only,
            "allowish": allowish, "denyish": denyish
        })

    # (1) Parameters
    for ep in details.endpoints:
        for p in ep.get('parameters', []) or []:
            if not isinstance(p, dict): 
                continue
            schema = p.get('schema') or {}
            name = p.get('name', '')
            desc = p.get('description') or schema.get('description') or ''
            t = str(schema.get("type","")).lower()
            fmt = str(schema.get("format","")).lower()
            looks_url = (t == "string" and (fmt in {"uri","url"} or _host_like_name(name) or "http" in desc.lower()))
            if not looks_url: 
                continue
            ok, ev = _patterns_ok(schema, desc)
            if not ok:
                findings.append({
                    "description": (f"URL-like parameter '{name}' in {ep['method']} {ep['path']} "
                                    f"lacks hardened constraints (https-only/allow-list/deny-list)."),
                    "schema": None, "field": name, "parameter": name, "header": None,
                    "endpoint": f"{ep['method']} {ep['path']}",
                    "evidence": {"parameter": p, **ev}
                })

    # (2) Request bodies (including oneOf/anyOf and hostname-only fields)
    for ep in details.endpoints:
        rb = ep.get('requestBody')
        for sname, sdef in _iter_request_body_schemas(spec, rb):
            # direct walk
            for prop_path, prop_def in _walk_properties(spec, sdef, _seen_nodes=set(), _seen_refs=set()):
                pname = prop_path.split(".")[-1].replace("[]","")
                desc = prop_def.get("description") or ""
                t = str(prop_def.get("type","")).lower()
                fmt = str(prop_def.get("format","")).lower()
                looks_url = (t == "string" and (fmt in {"uri","url"} or _host_like_name(pname) or "http" in desc.lower()))
                if not looks_url:
                    continue
                ok, ev = _patterns_ok(prop_def, desc)
                if not ok:
                    findings.append({
                        "description": (f"Request body URL-like field '{prop_path}' in {ep['method']} {ep['path']} "
                                        f"lacks hardened constraints (https-only/allow-list/deny-list)."),
                        "schema": sname, "field": prop_path, "parameter": None, "header": None,
                        "endpoint": f"{ep['method']} {ep['path']}",
                        "evidence": {"field_def": prop_def, **ev}
                    })
            # uri-like via oneOf/anyOf variants
            for ptr, sub, fname in _iter_uri_like_fields(spec, sdef, f"#/requestBodies/{sname}"):
                desc = sub.get("description") or ""
                ok, ev = _patterns_ok(sub, desc)
                if not ok:
                    findings.append({
                        "description": (f"URL-like variant '{fname}' (oneOf/anyOf) in {ep['method']} {ep['path']} "
                                        f"lacks hardened constraints (https-only/allow-list/deny-list)."),
                        "schema": sname, "field": fname, "parameter": None, "header": None,
                        "endpoint": f"{ep['method']} {ep['path']}",
                        "evidence": {"json_pointer": ptr, **ev}
                    })
    return findings

def check_unsafe_get_side_effects(details: OasDetails) -> List[Dict[str, Any]]:
    findings = []
    # Build a single regex from i18n verbs
    vocab = set()
    for words in (CONFIG.get("unsafe_verbs_i18n") or {}).values():
        for w in words:
            if w: vocab.add(str(w).strip().lower())
    if not vocab:
        vocab = {"create","assign","update","delete","modify","activate","reset","upload","issue","generate","provision","enroll","send"}
    pattern = r'\b(?:' + "|".join(sorted(re.escape(w) for w in vocab)) + r')\b'
    verbs_re = re.compile(pattern, re.I)

    for ep in details.endpoints:
        if ep['method'] != 'GET':
            continue
        text = f"{ep.get('summary','')} {ep.get('description','')}"
        looks_writey = bool(verbs_re.search(text))

        codes = {str(c) for c in (ep.get('responses') or {}).keys()}
        has_201_202 = bool({'201','202'} & codes)

        example_texts = list(_iter_operation_examples(details.spec(), ep))
        ex_writey = any(verbs_re.search(t or "") for t in example_texts)

        has_rb = bool(ep.get('requestBody'))

        if looks_writey or has_201_202 or ex_writey or has_rb:
            reasons = []
            if looks_writey: reasons.append("verbs/i18n")
            if has_201_202: reasons.append("201/202")
            if ex_writey: reasons.append("examples")
            if has_rb: reasons.append("requestBody")
            findings.append({
                "description": (f"GET {ep['path']} appears to create/modify state ({'; '.join(reasons)})."),
                "schema": None, "field": None, "parameter": None, "header": None,
                "endpoint": f"GET {ep['path']}",
                "evidence": {"summary": ep.get('summary'), "description": ep.get('description'),
                             "codes": sorted(codes), "examples_sample": example_texts[:2]}
            })
    return findings

def check_internal_reference_leakage(details: OasDetails) -> List[Dict[str, Any]]:
    findings = []
    for ep in details.endpoints:
        leaks = []
        for s in _iter_operation_examples(details.spec(), ep):
            if s and PRIVATE_HOST_RE.search(str(s)):
                leaks.append(s if len(s) <= 200 else (s[:197] + '...'))
        if leaks:
            findings.append({
                "description": f"{ep['method']} {ep['path']} examples reference internal hosts/private IPs.",
                "schema": None, "field": None, "parameter": None, "header": None,
                "endpoint": f"{ep['method']} {ep['path']}",
                "evidence": {"leaks": leaks[:5]}
            })
    return findings

# --- Policy and Parsing Logic ---
def load_rule_plugins(paths: List[str]) -> List[Tuple[str, Dict[str, Any], RuleFn]]:
    loaded: List[Tuple[str, Dict[str, Any], RuleFn]] = []

    def _load_plugin_inproc(py_path: str) -> List[Tuple[str, Dict[str, Any], RuleFn]]:
        triples: List[Tuple[str, Dict[str, Any], RuleFn]] = []
        fname = os.path.basename(py_path)
        try:
            mod_name = fname[:-3]
            spec = importlib.util.spec_from_file_location(mod_name, py_path)
            if spec is None or spec.loader is None:
                raise ImportError(f"Cannot create spec for {py_path}")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore

            # Preferred: explicit factory
            if hasattr(mod, "get_rules"):
                for r in (mod.get_rules() or []):
                    key = r["key"]; meta = r["meta"]; fn = r["run"]
                    triples.append((key, meta, fn))
            else:
                # Fallback: scan for annotated callables
                for name, obj in vars(mod).items():
                    if callable(obj) and getattr(obj, "_apex_rule", False):
                        key = getattr(obj, "_apex_key", name)
                        meta = getattr(obj, "_apex_meta", {})
                        triples.append((key, meta, obj))
        except Exception as e:
            logging.error(f"Failed to load plugin {py_path}: {e}")
        return triples

    for base in paths or []:
        if not base or not os.path.isdir(base):
            continue

        for fname in os.listdir(base):
            if not fname.endswith(".py"):
                continue

            fpath = os.path.join(base, fname)

            # Require signature if configured
            if CONFIG.get("require_signed_plugins") and not _verify_sidecar_sig(fpath):
                logging.warning(f"Skipping unsigned plugin: {fpath}")
                continue

            try:
                if CONFIG.get("sandbox_plugins"):
                    try:
                        triples = _run_plugin_sandboxed(fpath)  # provided elsewhere
                    except NameError:
                        # Sandbox helper not present; fall back to in-proc
                        logging.debug("Sandbox loader not found; falling back to in-proc.")
                        triples = _load_plugin_inproc(fpath)
                else:
                    triples = _load_plugin_inproc(fpath)

                for (key, meta, fn) in (triples or []):
                    loaded.append((key, meta, fn))
                    logging.info(f"Loaded plugin rule: {key} from {fname}")

            except Exception as e:
                logging.error(f"Failed to load plugin {fpath}: {e}")

    return loaded


def apply_policy_pack(packs: List[str]) -> Dict[str, Any]:
    custom_yaml_rules: List[Dict[str, Any]] = []
    loaded: Set[str] = set()

    def _load_one(path: str, stack: List[str]) -> Dict[str, Any]:
        if path in loaded:
            return {}
        if path in stack:
            raise RuntimeError(f"Policy pack cycle detected: {' -> '.join(stack + [path])}")
        with open(path, "r", encoding="utf-8") as f:
            y = yaml.safe_load(f) or {}

        # header
        name = y.get("name") or os.path.basename(path)
        version = y.get("version", "")
        parent = y.get("parent")
        signature = y.get("signature")

        if version and not _semver_ok(version):
            logging.warning(f"Policy pack '{name}' has non-SemVer version '{version}'.")
        if signature and not _verify_pack_signature(path, signature):
            logging.warning(f"Policy pack '{name}' signature verification FAILED.")

        # parent load (inherit)
        if parent:
            base_path = os.path.join(os.path.dirname(path), parent)
            _load_one(base_path, stack + [path])

        # apply overrides
        ov = (y.get("overrides") or {})
        sev = ov.get("severity") or {}
        dis = set(ov.get("disable") or [])
        if sev:
            CONFIG["override_severity"] = {**CONFIG.get("override_severity", {}), **sev}
        if dis:
            CONFIG["disable_rules"] = set(CONFIG.get("disable_rules", set())) | dis

        # collect custom YAML rules
        cr = y.get("custom_rules") or []
        for r in cr:
            if isinstance(r, dict):
                custom_yaml_rules.append(r)

        loaded.add(path)
        logging.info(f"Applied policy pack: {name} ({version}) from {path}")
        return y

    for pp in packs or []:
        try:
            if not pp or not os.path.isfile(pp):
                logging.error(f"Policy pack not found: {pp}")
                continue
            _load_one(pp, [])
        except Exception as e:
            logging.error(f"Failed to load policy pack {pp}: {e}")

    return {"yaml_rules": custom_yaml_rules}


def build_yaml_rule_fn(rule_def: Dict[str, Any]) -> Tuple[str, Dict[str, Any], RuleFn]:
    key = rule_def["key"]
    meta = {
        "owasp_api_top_10": rule_def.get("owasp", "ORG"),
        "name": rule_def.get("name", key),
        "severity": rule_def.get("severity", "Low"),
        "prefix": rule_def.get("prefix", "Policy"),
        "recommendation": rule_def.get("description", "Policy rule.")
    }
    rtype = rule_def.get("type")
    pattern = rule_def.get("pattern", "")
    cre = re.compile(pattern) if pattern else None

    def run(details: OasDetails) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if rtype == "path_regex" and cre:
            for ep in details.endpoints:
                if cre.search(ep["path"]):
                    out.append({
                        "description": f"Path '{ep['path']}' matched policy pattern /{pattern}/.",
                        "schema": None, "field": None, "parameter": None, "header": None,
                        "endpoint": f"{ep['method']} {ep['path']}",
                        "evidence": {"path": ep["path"], "pattern": pattern}
                    })
        elif rtype == "server_url_regex_forbidden" and cre:
            for s in details.get_servers():
                url = s.get("url", "")
                if isinstance(url, str) and cre.search(url):
                    out.append({
                        "description": f"Server URL '{url}' matched forbidden pattern /{pattern}/.",
                        "schema": None, "field": None, "parameter": None, "header": None,
                        "endpoint": "global",
                        "evidence": {"url": url, "pattern": pattern}
                    })
        return out

    return key, meta, run

SPECTRAL_TO_OUR = {"error": "High", "warn": "Medium", "info": "Low", "hint": "Low", "off": None}
OUR_TO_SPECTRAL = {"Critical": "error", "High": "error", "Medium": "warn", "Low": "info"}

def spectral_ingest(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            y = yaml.safe_load(f) or {}
        rules = y.get("rules", {}) or {}
        for rname, rdef in rules.items():
            if not rname.startswith("apex/"):
                continue
            key = rname.split("/",1)[1]
            if isinstance(rdef, dict):
                enabled = rdef.get("enabled", True)
                if enabled is False:
                    CONFIG["disable_rules"] = set(CONFIG.get("disable_rules", set())) | {key}
                sev = rdef.get("severity")
                if sev is not None:
                    mapped = SPECTRAL_TO_OUR.get(str(sev).lower())
                    if mapped:
                        CONFIG["override_severity"] = {**CONFIG.get("override_severity", {}), key: mapped}
        logging.info(f"Ingested Spectral ruleset from {path}")
    except Exception as e:
        logging.error(f"Failed to ingest Spectral ruleset {path}: {e}")

def spectral_export(path: str):
    rules = {}
    for k, meta in VULNERABILITY_MAP.items():
        our = CONFIG.get("override_severity", {}).get(k, meta.get("severity", "Low"))
        rules[f"apex/{k}"] = {
            "description": meta.get("name"),
            "message": f"APEX policy for {k}",
            "severity": OUR_TO_SPECTRAL.get(our, "info"),
            "given": "$",
            "then": [{"function": "truthy"}],
            "enabled": k not in CONFIG.get("disable_rules", set())
        }
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump({"extends": [], "rules": rules}, f, sort_keys=False)
    logging.info(f"Exported Spectral ruleset to {path}")

# Register built-ins
builtins = [
    check_broken_object_level_authorization, check_broken_authentication, check_sensitive_id_security,
    check_bopla_property_level_exposure, check_schema_sensitive_fields_exposure,
    check_doc_hint_rate_limit_headers, check_doc_hint_security_headers, check_security_misconfiguration,
    check_improper_inventory, check_unsafe_consumption,
    check_ssrf_query_params, check_ssrf_request_bodies, check_ssrf_server_variables,
    check_inventory_deprecated, check_inventory_versioning, check_inventory_mixed_servers,
    check_broken_function_level_authorization,
    check_auth_consistency, check_ssrf_hardening_fields, check_unsafe_get_side_effects, check_internal_reference_leakage
]
for fn in builtins:
    RULE_FUNCTIONS[fn.__name__] = fn

# Parallel safe keys
_PARALLEL_SAFE_KEYS = {
    "check_auth_consistency",
    "check_ssrf_hardening_fields",
    "check_unsafe_get_side_effects",
    "check_internal_reference_leakage",
    "check_ssrf_query_params",
    "check_ssrf_request_bodies",
    "check_ssrf_server_variables",
    "check_inventory_deprecated",
    "check_inventory_versioning",
    "check_inventory_mixed_servers",
    "check_improper_inventory",
    "check_security_misconfiguration",
}
for k in _PARALLEL_SAFE_KEYS:
    if k in RULE_FUNCTIONS:
        setattr(RULE_FUNCTIONS[k], "parallel_safe", True)
