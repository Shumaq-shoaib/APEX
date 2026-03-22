from urllib.parse import urlparse


class URLFilter:
    STATIC_EXTENSIONS = (
        '.css', '.js', '.woff', '.woff2', '.ttf', '.png', '.jpg', '.jpeg',
        '.svg', '.gif', '.ico', '.mp4', '.pdf', '.zip', '.tar.gz', '.webp',
    )

    def __init__(self, target_url):
        self.target_domain = urlparse(target_url).netloc

    def is_valid(self, url):
        parsed = urlparse(url)

        if parsed.netloc and parsed.netloc != self.target_domain:
            return False

        path = parsed.path.lower()
        if path.endswith(self.STATIC_EXTENSIONS):
            return False

        if path.startswith('/http://') or path.startswith('/https://'):
            return False

        return True
