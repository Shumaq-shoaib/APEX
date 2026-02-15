# -*- coding: utf-8 -*-
import re
import json
import logging
from typing import Dict, Any, List, Set, Iterable, Tuple, Optional
from datetime import datetime
from .config import CONFIG, SEVERITY_SCORES
from .models import OasDetails
from .utils import _resolve_ref, _merge_overlay, _example_too_large

def _flatten_findings(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for _ep, data in result.get("endpoints", {}).items():
        out.extend(data.get("vulnerabilities", []))
    return out

def load_baseline(path: str) -> Dict[str, int]:
    """
    Returns {fingerprint: severity_score} from a previous JSON report.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            r = json.load(f)
        mp = {}
        for ep in r.get("endpoints", []):
            for v in ep.get("vulnerabilities", []):
                mp[v.get("fingerprint")] = SEVERITY_SCORES.get(v.get("severity","Low"), 1)
        return mp
    except Exception as e:
        logging.error(f"Failed to load baseline {path}: {e}")
        return {}

# --- JSON Pointer helpers ---
def _escape_json_pointer(seg: str) -> str:
    return seg.replace("~", "~0").replace("/", "~1")

def _derive_op_pointer(method: str, path: str) -> str:
    # /paths/~1pets/get
    p = path if path.startswith("/") else f"/{path}"
    return f"/paths/{_escape_json_pointer(p)}/{method.lower()}"

def _traverse_pointer(doc: Dict[str, Any], ptr: str) -> Any:
    if not ptr or ptr == "#": return doc
    if ptr.startswith("#"): ptr = ptr[1:]
    if not ptr.startswith("/"): return None
    cur = doc
    for raw in ptr.split("/")[1:]:
        seg = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        else:
            return None
    return cur

# --- RBAC inference helpers ---
PRIV_VERBS = {
    "create":"write","add":"write","update":"write","patch":"write",
    "delete":"delete","remove":"delete","admin":"admin","approve":"admin","assign":"admin"
}
METHOD_PRIV = {"POST":"write","PUT":"write","PATCH":"write","DELETE":"delete"}

def _verb_implies_privileged(method: str, summary: str, desc: str) -> Set[str]:
    implied: Set[str] = set()
    if METHOD_PRIV.get(method):
        implied.add(METHOD_PRIV[method])
    text = f"{summary or ''} {desc or ''}".lower()
    for k, v in PRIV_VERBS.items():
        if re.search(rf'\b{k}\b', text):
            implied.add(v)
    return implied

def _resource_guess(tags: List[str], path: str) -> str:
    # prefer first tag; else last non-empty path segment (strip plural 's')
    if tags:
        return str(tags[0]).split(":")[0].lower()
    parts = [p for p in (path or "").split("/") if p and not p.startswith("{")]
    if parts:
        res = parts[-1].lower()
        return res[:-1] if res.endswith("s") and len(res) > 3 else res
    return "resource"

def _scope_match(required: Set[str], available_scopes: Set[str], resource: str) -> bool:
    # loose match: "{resource}:{write}" or wildcards like "admin:*" or "*:write"
    a = {s.lower() for s in available_scopes}
    if not required:
        return True
    for need in required:
        if need == "admin" and any(s.startswith("admin") for s in a):
            continue
        if need in {"write","delete"}:
            if any(s.endswith(":write") or s.endswith(":delete") for s in a):
                continue
            if any(s.startswith(f"{resource}:") and (s.endswith(":write") or s.endswith(":delete")) for s in a):
                continue
            return False
    return True

# --- URL-ish detection helpers for SSRF ---
_URL_HINT_RE = re.compile(r'\b(url|uri|endpoint|redirect|callback|webhook|target|link|image_url|avatar_url)s?\b', re.I)
_ALLOWLIST_RE = re.compile(r'\b(allow[-\s]?list|white[-\s]?list|approved|restrict(?:ed|ion)?|only)\b', re.I)

def _is_urlish_field(prop_name: str, prop_schema: Dict[str, Any], description: str = "") -> bool:
    t = (prop_schema.get("type") or "").lower()
    fmt = (prop_schema.get("format") or "").lower()
    name_hit = bool(_URL_HINT_RE.search(prop_name or ""))
    desc = description or prop_schema.get("description") or ""
    desc_hit = "http" in desc.lower() or "https" in desc.lower() or _URL_HINT_RE.search(desc or "") is not None
    return (t == "string") and (fmt in {"uri", "url"} or name_hit or desc_hit)

def _has_allowlist_language(text: str) -> bool:
    return bool(_ALLOWLIST_RE.search(text or ""))

# --- Richer SSRF helpers ---
URI_LIKE_NAMES = {
    "url","uri","image_url","avatar_url","redirect","webhook","endpoint",
    "callback","target","origin","baseUrl","base_url","authority",
    "host","hostname","domain"
}

# Accept (?:https://|wss://) and anchored groups/variants
HTTPS_OK_GROUP = re.compile(r'^\^?(?:\(\?:)?(?:https://|wss://)', re.I)

def _is_https_only_pattern(p: str) -> bool:
    p = (p or "").strip()
    if not p:
        return False
    # direct ^https:// or ^(?:https://|wss://) styles
    if re.search(r'^\^?(?:https://|wss://)', p, re.I):
        return True
    return bool(HTTPS_OK_GROUP.search(p))

def _host_like_name(name: str) -> bool:
    n = (name or "").lower()
    return (n in URI_LIKE_NAMES) or any(k in n for k in ("host","hostname","domain","authority","origin"))

RFC1918_OR_META = re.compile(
    r'(?:^|[^\d])(127\.0\.0\.1|localhost|169\.254\.169\.254|'
    r'10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+)'
    r'(?:$|[^\d])',
    re.I
)

def _rfc1918_or_meta_ip(s: str) -> bool:
    return bool(RFC1918_OR_META.search(s or ""))

def _iter_uri_like_fields(spec: Dict[str, Any], schema: Dict[str, Any], base_ptr: str) -> Iterable[Tuple[str, Dict[str, Any], str]]:
    """
    Yield (json_pointer, subschema, field_name) for anything that *looks* like a URL/host
    """
    if not isinstance(schema, dict):
        return
    # direct node checks (RFC components)
    rfc_components = {"scheme","userinfo","host","port","path","query","fragment"}
    props = schema.get("properties", {}) or {}
    for pname, pdef in props.items():
        pdef = pdef or {}
        ptr = f"{base_ptr}/properties/{pname}"
        t = str(pdef.get("type","")).lower()
        fmt = str(pdef.get("format","")).lower()
        name_hit = _host_like_name(pname)
        rfc_hit = pname in rfc_components
        pattern_present = isinstance(pdef.get("pattern"), str) and pdef.get("pattern")
        looks_url = (t == "string" and (fmt in {"uri","url"} or pattern_present or name_hit or rfc_hit))
        if looks_url:
            yield (ptr, pdef, pname)

        # arrays of url-like?
        if t == "array" and isinstance(pdef.get("items"), dict):
            items = pdef["items"]
            it_fmt = str(items.get("format","")).lower()
            it_ptr = f"{ptr}/items"
            if it_fmt in {"uri","url"} or _host_like_name(pname):
                yield (it_ptr, items, pname)

    # dive oneOf/anyOf
    for k in ("oneOf","anyOf"):
        for idx, v in enumerate(schema.get(k, []) or []):
            node = v
            if isinstance(v, dict) and "$ref" in v:
                _n, target = _resolve_ref(spec, v["$ref"])
                node = _merge_overlay(target, v)
            if isinstance(node, dict):
                yield from _iter_uri_like_fields(spec, node, f"{base_ptr}/{k}/{idx}")

# --- EXTRA: internal/private host detection & examples traversal ---
PRIVATE_HOST_RE = re.compile(
    r'(?i)\b('
    r'localhost|\[::1\]|127\.0\.0\.1|'
    r'10\.(?:\d{1,3}\.){2}\d{1,3}|'
    r'192\.168\.(?:\d{1,3}\.)\d{1,3}|'
    r'172\.(?:1[6-9]|2\d|3[0-1])\.(?:\d{1,3}\.)\d{1,3}|'
    r'169\.254\.(?:\d{1,3}\.)\d{1,3}|'
    r'169\.254\.169\.254|'                   # cloud metadata IP
    r'(?:[a-z0-9-]+\.)+(?:internal|corp|local|svc\.cluster\.local)'
    r')\b'
)

def _endpoint_tags(ep: Dict[str, Any]) -> List[str]:
    ts = ep.get('tags')
    if isinstance(ts, list) and ts:
        return [str(t) for t in ts if t]
    return ['<untagged>']

def _collect_texts_from_obj(x: Any) -> List[str]:
    out = []
    if x is None:
        return out
    if isinstance(x, str):
        out.append(x)
    elif isinstance(x, (int, float, bool)):
        out.append(str(x))
    elif isinstance(x, (list, tuple, set)):
        for i in x:
            out.extend(_collect_texts_from_obj(i))
    elif isinstance(x, dict):
        if 'value' in x:
            out.extend(_collect_texts_from_obj(x.get('value')))
        else:
            for v in x.values():
                out.extend(_collect_texts_from_obj(v))
    return out


def _iter_media_examples(media: Dict[str, Any]) -> Iterable[str]:
    if not isinstance(media, dict):
        return
    if 'example' in media:
        for s in _collect_texts_from_obj(media.get('example')):
            if not _example_too_large(s):
                yield s
    if 'examples' in media and isinstance(media['examples'], dict):
        for ex in media['examples'].values():
            for s in _collect_texts_from_obj(ex):
                if not _example_too_large(s):
                    yield s

def _iter_operation_examples(spec: Dict[str, Any], ep: Dict[str, Any]) -> Iterable[str]:
    # Parameters
    for p in ep.get('parameters', []) or []:
        if isinstance(p, dict):
            for k in ('example', 'examples', 'schema', 'content'):
                if k in p:
                    for s in _collect_texts_from_obj(p[k]):
                        if not _example_too_large(s):
                            yield s
    # Request body
    rb = ep.get('requestBody')
    if rb:
        if isinstance(rb, dict) and '$ref' in rb:
            _n, rb = _resolve_ref(spec, rb['$ref'])
        content = (rb or {}).get('content', {})
        if isinstance(content, dict):
            for _mt, media in content.items():
                for s in _iter_media_examples(media):
                    if not _example_too_large(s):
                        yield s
    # Responses
    for r in ep.get('responses', {}).values():
        if not isinstance(r, dict):
            continue
        content = r.get('content', {})
        if isinstance(content, dict):
            for _mt, media in content.items():
                for s in _iter_media_examples(media):
                    if not _example_too_large(s):
                        yield s

def _parse_date_yyyy_mm_dd(d: str) -> Optional[datetime]:
    try:
        return datetime.strptime(d.strip(), "%Y-%m-%d")
    except ValueError:
        return None

def is_suppressed(details: OasDetails, pointer: str, check_key: str) -> Tuple[bool, Dict[str, Any]]:
    """
    Looks for:
      x-apex-ignore: ["rule_key", ...]
      x-apex-justification: "why"
      x-apex-expiry: "YYYY-MM-DD"  # optional
    Walks the JSON Pointer; if not found, tries parent nodes up to the operation root.
    """
    spec = details.spec()
    node_ptr = pointer or ""
    tried = []
    while node_ptr:
        node = _traverse_pointer(spec, node_ptr)
        tried.append(node_ptr)
        if isinstance(node, dict):
            ig = node.get("x-apex-ignore")
            if isinstance(ig, list) and check_key in {str(x) for x in ig}:
                just = node.get("x-apex-justification", "")
                exp = node.get("x-apex-expiry")
                if exp:
                    dt = _parse_date_yyyy_mm_dd(str(exp))
                    if dt and datetime.now().date() > dt.date():
                        # expired → do not suppress
                        return (False, {"reason": "expired", "pointer": node_ptr, "expiry": exp, "justification": just})
                return (True, {"reason": "inline-suppression", "pointer": node_ptr, "expiry": exp, "justification": just})
        # trim one level up
        if "/" not in node_ptr.strip("/"):
            break
        node_ptr = "/" + "/".join(node_ptr.strip("/").split("/")[:-1])
    return (False, {"checked": tried})

# --- Other helpers found in file ---
def _extract_path_params_from_path(path: str) -> List[str]:
    return re.findall(r'\{([^}/]+)\}', path or "")

def _is_sensitive_id_name(name: str) -> bool:
    if not name:
        return False
    nl = name.lower()
    if nl in CONFIG["sensitive_id_keywords"]:
        return True
    return nl == "id" or nl.endswith("id")

def _collect_operation_scopes(op_security: Any) -> Set[str]:
    scopes: Set[str] = set()
    if isinstance(op_security, list):
        for req in op_security:
            if isinstance(req, dict):
                for _scheme, scheme_scopes in req.items():
                    if isinstance(scheme_scopes, list):
                        scopes.update(str(s).strip() for s in scheme_scopes if s is not None)
                    elif scheme_scopes is None:
                        scopes.add("")  # no scopes = broad
    return scopes

def _is_unconstrained_object(s: Dict[str, Any]) -> bool:
    if not isinstance(s, dict) or (s.get("type") != "object"):
        return False
    ap = s.get("additionalProperties", None)
    # true or {} means unconstrained (or dict without internal typing)
    return ap is True or ap == {} or (isinstance(ap, dict) and not ap.get("type") and not ap.get("properties"))

def _extract_vendor_scopes(prop_schema: Dict[str, Any]) -> Set[str]:
    scopes = set()
    for k in CONFIG["vendor_scope_keys"]:
        v = prop_schema.get(k)
        if isinstance(v, str):
            scopes.add(v.strip())
        elif isinstance(v, list):
            scopes.update(str(x).strip() for x in v if x is not None)
    return scopes

def _is_vendor_sensitive(prop_schema: Dict[str, Any]) -> bool:
    for k in CONFIG["vendor_sensitive_keys"]:
        v = prop_schema.get(k)
        if isinstance(v, bool) and v:
            return True
        if isinstance(v, str) and v.lower() in {"true","yes","sensitive","internal"}:
            return True
    if str(prop_schema.get("format","")).lower() == "password":
        return True
    return False

def _is_keyword_sensitive(prop_name: str) -> bool:
    return prop_name.lower() in CONFIG["sensitive_keywords"]

def _looks_broad(scopes: Set[str]) -> bool:
    if "" in scopes:
        return True
    lower = {s.lower() for s in scopes}
    return any(marker in ",".join(lower) for marker in CONFIG["broad_scope_markers"])

def _has_privileged(scopes: Set[str]) -> bool:
    lower = {s.lower() for s in scopes}
    return any(marker in ",".join(lower) for marker in CONFIG["privileged_scope_markers"])

def _endpoint_method_path(detail: Dict[str, Any]) -> Tuple[str, str]:
    ep = (detail.get("endpoint") or "").strip()
    if " " in ep:
        m, p = ep.split(" ", 1)
        return m.upper(), p
    return "", ep

