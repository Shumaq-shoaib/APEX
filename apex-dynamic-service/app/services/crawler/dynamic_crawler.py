from playwright.async_api import async_playwright


class DynamicCrawler:
    def __init__(self):
        self.intercepted_endpoints = set()

    async def crawl(self, url):
        """Launch headless Chromium, visit URL, intercept all network requests."""
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            page.on("request", lambda request: self.intercepted_endpoints.add(request.url))

            try:
                await page.goto(url, wait_until="networkidle", timeout=30000)
            except Exception:
                pass

            await browser.close()
            return self.intercepted_endpoints
