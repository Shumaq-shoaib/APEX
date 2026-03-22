from urllib.parse import urlparse, parse_qs


def generate_blueprint(endpoints_set):
    """Generate an APEX-compatible blueprint JSON from a set of endpoint strings."""
    blueprint = {"endpoints": []}

    for url in endpoints_set:
        parsed = urlparse(url)
        path = parsed.path

        params = []
        if parsed.query:
            query_vars = parse_qs(parsed.query)
            for key in query_vars.keys():
                params.append({"name": key, "in": "query"})

        blueprint["endpoints"].append({
            "path": path,
            "method": "GET",
            "params": params,
            "source": "apex-crawler",
        })

    return blueprint
