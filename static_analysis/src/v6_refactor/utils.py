# -*- coding: utf-8 -*-
import os
import yaml
import json
import logging
import re
from typing import Dict, Any, Tuple, Iterable, Set, List
from .config import CONFIG

# per-run caches
_RESOLVE_CACHE: Dict[Tuple[int, str], Tuple[str, Dict[str, Any]]] = {}
_MERGE_ALLOF_CACHE: Dict[Tuple[int, int], Dict[str, Any]] = {}
_WALK_CACHE: Dict[Tuple[int, int], List[Tuple[str, Dict[str, Any]]]] = {}

def reset_caches():
    _RESOLVE_CACHE.clear()
    _MERGE_ALLOF_CACHE.clear()
    _WALK_CACHE.clear()

def _resolve_ref(spec: Dict[str, Any], ref: str, _depth: int = 0) -> Tuple[str, Dict[str, Any]]:
    if _depth > int(CONFIG.get("max_ref_depth", 32)) or not isinstance(ref, str):
        return ("<inline>", {})
    # internal
    if ref.startswith("#/"):
        key = (id(spec), ref)
        if key in _RESOLVE_CACHE: return _RESOLVE_CACHE[key]
        parts = ref.lstrip("#/").split("/")
        node = spec
        for p in parts: node = node.get(p, {})
        res = (parts[-1] if parts else "<inline>", node if isinstance(node, dict) else {})
        _RESOLVE_CACHE[key] = res
        return res
    # file:
    if ref.startswith("file:"):
        path = ref[len("file:"):]
        if not os.path.isabs(path):
            base = os.path.dirname(spec.get("__file_path__","") or os.getcwd())
            path = os.path.normpath(os.path.join(base, path))
        try:
            with open(path, "r", encoding="utf-8") as f:
                ext = os.path.splitext(path)[1].lower()
                doc = yaml.safe_load(f) if ext in (".yaml",".yml") else json.load(f)
            return ("<file>", doc if isinstance(doc, dict) else {})
        except Exception:
            return ("<file>", {})
    # http(s):
    if ref.startswith("http://") or ref.startswith("https://"):
        from urllib.parse import urlparse
        host = urlparse(ref).hostname or ""
        if host not in set(CONFIG.get("allowed_remote_ref_domains", [])):
            logging.debug(f"remote $ref blocked (not allow-listed): {ref}")
            return ("<remote>", {})
        try:
            import urllib.request
            with urllib.request.urlopen(ref, timeout=5) as r:
                data = r.read()
            try:
                doc = json.loads(data)
            except Exception:
                doc = yaml.safe_load(data) or {}
            return ("<remote>", doc if isinstance(doc, dict) else {})
        except Exception as e:
            logging.debug(f"remote $ref fetch failed: {e}")
            return ("<remote>", {})
    return ("<inline>", {})


def _merge_overlay(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base or {})
    for k, v in (overlay or {}).items():
        if k == '$ref':
            continue
        out[k] = v
    return out

def _merge_allOf(schema: Dict[str, Any], spec: Dict[str, Any], _seen_refs: Set[str]) -> Dict[str, Any]:
    """
    Cached by (id(spec), id(schema)) — safe because we only read dicts.
    Produces union of properties + required (already in your version).
    """
    if not isinstance(schema, dict):
        return {}
    cache_key = (id(spec), id(schema))
    if cache_key in _MERGE_ALLOF_CACHE:
        return _MERGE_ALLOF_CACHE[cache_key]

    out = dict(schema)
    props = dict(schema.get('properties', {}))
    required = set(schema.get('required', []) or [])
    for comp in schema.get('allOf', []) or []:
        if '$ref' in comp:
            ref = comp['$ref']
            if ref in _seen_refs:
                continue
            _seen_refs.add(ref)
            _n, target = _resolve_ref(spec, ref)
            target = _merge_allOf(target, spec, _seen_refs)
        else:
            target = comp
        if isinstance(target, dict):
            props.update(target.get('properties', {}) or {})
            required |= set(target.get('required', []) or [])
    out['properties'] = props
    if required:
        out['required'] = sorted(required)

    _MERGE_ALLOF_CACHE[cache_key] = out
    return out


def _walk_properties(
    spec: Dict[str, Any],
    schema: Dict[str, Any],
    base: str = "",
    _seen_nodes: Set[int] = None,
    _seen_refs: Set[str] = None
) -> Iterable[Tuple[str, Dict[str, Any]]]:
    """
    Walk properties and yield (path, schema). For speed, cache the **relative** walk for this schema id
    when base == "" and reuse later (prefixing on demand).
    """
    if _seen_nodes is None: _seen_nodes = set()
    if _seen_refs is None: _seen_refs = set()
    if not isinstance(schema, dict):
        return

    # cached relative walk (only for base == "")
    if base == "":
        ck = (id(spec), id(schema))
        cached = _WALK_CACHE.get(ck)
        if cached is not None:
            for rel_path, pdef in cached:
                yield (rel_path, pdef)
            return

    sid = id(schema)
    if sid in _seen_nodes:
        return
    _seen_nodes.add(sid)

    # inline $ref resolve/overlay
    if '$ref' in schema:
        ref = schema['$ref']
        if ref not in _seen_refs:
            _seen_refs.add(ref)
            _n, target = _resolve_ref(spec, ref)
            schema = _merge_overlay(target, schema)

    if 'allOf' in schema:
        schema = _merge_allOf(schema, spec, set(_seen_refs))

    results: List[Tuple[str, Dict[str, Any]]] = []

    props = schema.get('properties', {})
    if isinstance(props, dict):
        for pname, pdef in props.items():
            path = f"{base}.{pname}" if base else pname
            # resolve nested $ref
            if isinstance(pdef, dict) and '$ref' in pdef:
                ref = pdef['$ref']
                if ref in _seen_refs:
                    merged = {k: v for k, v in pdef.items() if k != '$ref'}
                else:
                    _seen_refs.add(ref)
                    _n, target = _resolve_ref(spec, ref)
                    merged = _merge_overlay(target, pdef)
                results.append((path, merged if isinstance(merged, dict) else {}))
                if isinstance(merged, dict):
                    ptype = merged.get('type')
                    if ptype == 'object':
                        results.extend(_walk_properties(spec, merged, path, _seen_nodes, _seen_refs))
                    elif ptype == 'array' and isinstance(merged.get('items'), dict):
                        results.extend(_walk_properties(spec, merged['items'], f"{path}[]", _seen_nodes, _seen_refs))
                continue

            results.append((path, pdef if isinstance(pdef, dict) else {}))
            if isinstance(pdef, dict):
                ptype = pdef.get('type')
                if ptype == 'object':
                    results.extend(_walk_properties(spec, pdef, path, _seen_nodes, _seen_refs))
                elif ptype == 'array' and isinstance(pdef.get('items'), dict):
                    results.extend(_walk_properties(spec, pdef['items'], f"{path}[]", _seen_nodes, _seen_refs))

    # oneOf/anyOf
    for key in ('oneOf', 'anyOf'):
        variants = schema.get(key, []) or []
        for v in variants:
            if '$ref' in v:
                ref = v['$ref']
                if ref in _seen_refs:
                    continue
                _seen_refs.add(ref)
                _n, target = _resolve_ref(spec, ref)
            else:
                target = v
            if isinstance(target, dict):
                results.extend(_walk_properties(spec, target, base, _seen_nodes, _seen_refs))

    # write-through cache for base == ""
    if base == "":
        _WALK_CACHE[(id(spec), id(schema))] = results

    for item in results:
        yield item


def _iter_response_schemas(spec: Dict[str, Any], responses_obj: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    if not isinstance(responses_obj, dict):
        return
    for _code, r in responses_obj.items():
        if not isinstance(r, dict):
            continue
        content = r.get('content', {})
        if not isinstance(content, dict):
            continue
        for mt, media in content.items():
            if not isinstance(media, dict):
                continue
            if any(str(mt).lower().startswith(x) for x in CONFIG["json_media_types"]):
                schema = media.get('schema')
                if not schema:
                    continue
                if isinstance(schema, dict) and '$ref' in schema:
                    sname, sdef = _resolve_ref(spec, schema['$ref'])
                    if sdef: yield (sname, sdef)
                elif isinstance(schema, dict):
                    yield ("<inline>", schema)

def _iter_request_body_schemas(spec: Dict[str, Any], rb_obj: Any) -> Iterable[Tuple[str, Dict[str, Any]]]:
    if not rb_obj:
        return
    rb = rb_obj
    if isinstance(rb_obj, dict) and '$ref' in rb_obj:
        _n, rb = _resolve_ref(spec, rb_obj['$ref'])
    if not isinstance(rb, dict):
        return
    content = rb.get('content', {})
    if not isinstance(content, dict):
        return
    for mt, media in content.items():
        if not isinstance(media, dict):
            continue
        if any(str(mt).lower().startswith(x) for x in CONFIG["json_media_types"]):
            schema = media.get('schema')
            if not schema:
                continue
            if isinstance(schema, dict) and '$ref' in schema:
                sname, sdef = _resolve_ref(spec, schema['$ref'])
                if sdef: yield (sname, sdef)
            elif isinstance(schema, dict):
                yield ("<inline>", schema)


def _example_too_large(s: str) -> bool:
    try:
        return len(str(s).encode("utf-8")) > int(CONFIG.get("max_example_bytes", 2 * 1024 * 1024))
    except Exception:
        return False

# --- Filesystem / Plugin helpers ---
def _run_plugin_sandboxed(py_path: str):
    import multiprocessing as mp, builtins, socket
    def _worker(path, q):
        _open = builtins.open
        def _open_ro(*a, **kw):
            if 'w' in kw.get('mode','') or 'a' in kw.get('mode','') or '+' in kw.get('mode',''):
                raise PermissionError("sandbox: write denied")
            return _open(*a, **kw)
        builtins.open = _open_ro
        socket.socket = lambda *a, **kw: (_ for _ in ()).throw(PermissionError("sandbox: net denied"))
        ns = {}
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()
        exec(compile(code, path, "exec"), ns, ns)
        out = []
        for k, v in ns.items():
            if getattr(v, "_apex_rule", False):
                out.append((k, getattr(v, "_apex_meta", {}), v))
        q.put(out)
    q = mp.Queue()
    p = mp.Process(target=_worker, args=(py_path, q))
    p.start(); p.join(timeout=10)
    if p.is_alive():
        p.terminate()
        logging.warning(f"Plugin timed out: {py_path}")
        return []
    try:
        return q.get_nowait()
    except Exception:
        return []

import hashlib

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1<<16), b""):
            h.update(chunk)
    return h.hexdigest()

def _verify_sidecar_sig(py_path: str) -> bool:
    sig_path = py_path + ".sig"
    if not os.path.isfile(sig_path): return False
    with open(sig_path, "r", encoding="utf-8") as f:
        sig = f.read().strip().lower()
    if sig.startswith("sha256:"):
        sig = sig.split("sha256:",1)[1]
    return _sha256_file(py_path).lower() == sig

_SEMVER_RE = re.compile(r'^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$')

import re
def _semver_ok(v: str) -> bool:
    return bool(_SEMVER_RE.match(str(v or "").strip()))

def _verify_pack_signature(path: str, sig: str) -> bool:
    try:
        sha = _sha256_file(path)
        s = (sig or "").lower().strip()
        s = s.split("sha256:",1)[-1] if "sha256:" in s else s
        return sha.lower() == s
    except Exception:
        return False
