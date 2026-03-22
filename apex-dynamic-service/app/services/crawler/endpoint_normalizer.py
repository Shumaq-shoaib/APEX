from urllib.parse import urlparse, parse_qs, urlencode


def normalize_url(url):
    """Normalize a URL: strip cache-buster params and convert to relative path."""
    parsed = urlparse(url)

    query = parse_qs(parsed.query, keep_blank_values=True)
    for buster in ['ver', 'v', '_', 'timestamp']:
        query.pop(buster, None)

    new_query = urlencode(query, doseq=True)

    path = parsed.path if parsed.path else "/"
    if not path.startswith("/"):
        path = "/" + path

    if '/http://' in path or '/https://' in path:
        return None

    return f"{path}?{new_query}" if new_query else path
