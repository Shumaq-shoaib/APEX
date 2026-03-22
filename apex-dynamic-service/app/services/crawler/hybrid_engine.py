from .static_crawler import StaticCrawler
from .dynamic_crawler import DynamicCrawler
from .url_filters import URLFilter
from .endpoint_normalizer import normalize_url
import httpx


class HybridEngine:
    def __init__(self, target):
        self.target = target
        self.static = StaticCrawler(target)
        self.dynamic = DynamicCrawler()
        self.endpoints = set()
        self.url_filter = URLFilter(target)

    def _add_filtered(self, raw_endpoints):
        """Filter out-of-scope and static assets, then normalize."""
        for raw in raw_endpoints:
            if self.url_filter.is_valid(raw):
                normalized = normalize_url(raw)
                if normalized is not None:
                    self.endpoints.add(normalized)

    async def crawl(self):
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15.0) as client:
                response = await client.get(self.target)
                html_content = response.text

                html_endpoints, script_srcs = self.static.parse_html(html_content)
                self._add_filtered(html_endpoints)

                inline_js_endpoints = self.static.parse_js(html_content)
                self._add_filtered(inline_js_endpoints)

        except Exception:
            pass

        try:
            dynamic_endpoints = await self.dynamic.crawl(self.target)
            self._add_filtered(dynamic_endpoints)
        except Exception:
            pass

        return self.endpoints
