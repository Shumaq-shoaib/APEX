from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re


class StaticCrawler:
    def __init__(self, base_url):
        self.base_url = base_url

    def parse_html(self, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        endpoints = set()
        scripts = set()

        for a in soup.find_all('a', href=True):
            href = a['href']
            endpoints.add(href)

        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src:
                scripts.add(src)

        return endpoints, scripts

    def parse_js(self, js_content):
        """Extract API endpoints from JavaScript source code using regex patterns."""
        endpoints = set()

        # Pattern 1: Paths starting with / inside quotes (most common)
        path_pattern = re.compile(r'''["'](\/[a-zA-Z0-9_\-/.]+(?:\?[^"']*)?)['"]\s*''')
        for match in path_pattern.finditer(js_content):
            path = match.group(1)
            if not path.endswith(('.css', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff', '.woff2')):
                endpoints.add(path)

        # Pattern 2: fetch/axios/xhr calls with string URLs
        api_call_pattern = re.compile(
            r'''(?:fetch|axios\.(?:get|post|put|delete|patch)|\.open)\s*\(\s*["'](\/[^"']+)["']''',
            re.IGNORECASE
        )
        for match in api_call_pattern.finditer(js_content):
            endpoints.add(match.group(1))

        # Pattern 3: URL assignments (const url = "/api/...")
        assign_pattern = re.compile(
            r'''(?:url|path|endpoint|route|api|href)\s*[:=]\s*["'](\/[^"']+)["']''',
            re.IGNORECASE
        )
        for match in assign_pattern.finditer(js_content):
            endpoints.add(match.group(1))

        return endpoints
