def get_rules():
    def run(details):
        # Example: flag any path containing "/experimental"
        out = []
        for ep in details.endpoints:
            if "/experimental" in ep["path"]:
                out.append({
                    "description": f"Experimental path should not be published: {ep['method']} {ep['path']}",
                    "endpoint": f"{ep['method']} {ep['path']}",
                    "schema": None, "field": None, "parameter": None, "header": None,
                    "evidence": {"path": ep["path"]}
                })
        return out

    return [{
        "key": "org.experimental.forbidden",
        "meta": {
            "owasp_api_top_10": "ORG",
            "name": "Forbidden Experimental Paths",
            "severity": "High",
            "prefix": "Policy",
            "recommendation": "Remove experimental endpoints from public specs."
        },
        "run": run
    }]
    x