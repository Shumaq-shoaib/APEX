import hashlib
from datetime import datetime, timezone
import logging

def _resolve_security_schemes(global_sec, op_sec, components):
    """
    Resolve security requirements to concrete schemes (e.g., 'petstore_auth' -> 'oauth2').
    Returns a combined list of active schemes for the operation.
    """
    # Operation security overrides global; if op_sec is [], security is disabled.
    # If op_sec is None, use global.
    active_sec = op_sec if op_sec is not None else global_sec
    
    if not active_sec:
        return {"schemes": [], "types": []}

    resolved_schemes = []
    types = set()
    
    security_definitions = components.get("securitySchemes", {}) or components.get("securityDefinitions", {})

    for sec_req in active_sec:
        # sec_req is like {"petstore_auth": ["read:pets"]}
        for scheme_name, scopes in sec_req.items():
            scheme_def = security_definitions.get(scheme_name, {})
            s_type = scheme_def.get("type", "unknown").lower()
            s_scheme = scheme_def.get("scheme", "").lower() # for http (bearer, basic)
            
            # Normalize type for Dynamic Engine
            # e.g. http+bearer, oauth2, apiKey
            if s_type == "http":
                full_type = f"http_{s_scheme}" if s_scheme else "http"
            else:
                full_type = s_type

            types.add(full_type)
            resolved_schemes.append({
                "name": scheme_name,
                "type": full_type,
                "scopes": scopes,
                "in": scheme_def.get("in"), # header, query
                "key": scheme_def.get("name") # actual header name e.g. X-API-KEY
            })

    return {
        "schemes": resolved_schemes,
        "types": list(types)
    }

def generate_blueprint(details, results=None):
    """
    Generate a JSON blueprint for the Dynamic Engine.
    :param details: OasDetails instance
    :param results: (Optional) Static analysis findings to enrich risk profile
    """
    spec = details.spec()
    endpoints = details.endpoints
    
    # 1. Metadata
    generated_at = datetime.now(timezone.utc).isoformat()
    spec_str = str(spec).encode('utf-8')
    spec_hash = hashlib.sha256(spec_str).hexdigest()
    
    info = spec.get("info", {})
    
    # 2. Servers
    servers = [s.get("url") for s in spec.get("servers", [])]
    if not servers:
        # Fallback if no server defined
        host = spec.get("host") # Swagger 2.0
        basePath = spec.get("basePath", "/")
        schemes = spec.get("schemes", ["http"])
        if host:
            servers = [f"{s}://{host}{basePath}" for s in schemes]
    
    # 3. Endpoints
    blueprint_endpoints = []
    
    components = spec.get("components", {})
    # Handle Swagger 2.0 root-level definitions if needed, but OasDetails normalizes somewhat.
    # For securitySchemes, OasDetails doesn't expose components directly, so accessing spec.
    
    for ep in endpoints:
        path = ep["path"]
        method = ep["method"]
        
        # Resolve Authentication
        sec_info = _resolve_security_schemes(
            ep["global_security"], 
            ep["op_security_raw"], 
            components
        )
        
        # Resolve Parameters (simple list for fuzzing)
        fuzzable_params = []
        for p in ep["parameters"]:
            fuzzable_params.append({
                "name": p.get("name"),
                "in": p.get("in"),
                "type": p.get("schema", {}).get("type", "string"),
                "required": p.get("required", False)
            })

        # Risk Profile (if static results available)
        risk = "Unknown"
        issues = []
        if results and "endpoints" in results:
            # Map back finding to endpoint logic (simplified)
            # In Scanner, results["endpoints"] is a list.
            # We need to match precise path/method or use the scanner's keying.
            pass # TODO: Enhanced linking if needed later

        blueprint_endpoints.append({
            "path": path,
            "method": method,
            "auth": sec_info,
            "params": fuzzable_params,
            "risk": {
                "static_analysis_issues": len(issues)
            }
        })

    return {
        "meta": {
            "title": info.get("title", "Untitled"),
            "version": info.get("version", "0.0.0"),
            "spec_hash": spec_hash,
            "generated_at": generated_at,
            "apiex_version": "v6.0.0"
        },
        "target": {
            "servers": servers,
            "preferred_base_url": servers[0] if servers else None
        },
        "endpoints": blueprint_endpoints
    }
