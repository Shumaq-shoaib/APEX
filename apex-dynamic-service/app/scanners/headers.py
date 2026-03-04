import re
from typing import List, Dict, Any

from app.scanners.base import BaseScanner
from app.scanner_utils.http import HttpUtils

class SecurityHeadersScanner(BaseScanner):
    @property
    def scan_id(self) -> str:
        return "APEX-HEADERS"

    @property
    def name(self) -> str:
        return "Security Headers & Configuration Scanner"

    @property
    def category(self) -> str:
        return "API7:2023 Security Misconfiguration"

    @property
    def description(self) -> str:
        return "Analyzes HTTP response headers to detect missing security headers (e.g., CSP, HSTS, X-Frame-Options), insecure cookies, and server version disclosures."

    def run(self, endpoint: str, method: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.results = []
        target_url = f"{self.context.target_url.rstrip('/')}{endpoint}"

        # Send a single baseline request to analyze headers and cookies
        record = HttpUtils.send_request_recorded(
            method=method, url=target_url, auth=self.context.auth
        )
        
        if not record or not record.response_headers:
            return self.results

        # Case-insensitive headers lookup
        headers_lower = {k.lower(): v for k, v in record.response_headers.items()}

        # 1. Missing Security Headers
        required_headers = {
            "Content-Security-Policy": "Helps prevent XSS and data injection attacks by defining allowed content sources.",
            "X-Content-Type-Options": "Prevents MIME-sniffing, forcing the browser to stick to the declared Content-Type.",
            "Strict-Transport-Security": "Enforces secure (HTTP over SSL/TLS) connections to the server.",
            "X-Frame-Options": "Protects against Clickjacking by indicating whether the browser should be allowed to render a page in a <frame>, <iframe>, or <object>."
        }

        for header, usage in required_headers.items():
            if header.lower() not in headers_lower:
                self.add_finding(
                    record=record,
                    title=f"Missing Security Header: {header}",
                    description=f"The HTTP response is missing the '{header}' header. {usage}",
                    severity="Low",
                    evidence=f"Headers received do not contain {header}."
                )

        # 2. Misconfigured Headers
        # X-XSS-Protection
        xss_prot = headers_lower.get("x-xss-protection")
        if xss_prot:
            xss_prot_clean = xss_prot.replace(" ", "")
            if xss_prot_clean == "0":
                self.add_finding(
                    record=record,
                    title="Insecure X-XSS-Protection Header",
                    description="The X-XSS-Protection header is explicitly disabled (0), which turns off the browser's built-in XSS filter.",
                    severity="Low",
                    evidence=f"X-XSS-Protection: {xss_prot}"
                )
            elif xss_prot_clean != "1;mode=block":
                self.add_finding(
                    record=record,
                    title="Misconfigured X-XSS-Protection Header",
                    description="The X-XSS-Protection header should be set to '1; mode=block' for maximum security.",
                    severity="Low",
                    evidence=f"X-XSS-Protection: {xss_prot}"
                )

        # 3. Server Version Disclosure
        version_headers = ["server", "x-powered-by", "x-aspnet-version"]
        for vh in version_headers:
            if vh in headers_lower:
                header_val = headers_lower[vh]
                # If it contains digits, it's likely disclosing a specific version number
                if re.search(r'\d', header_val):
                    self.add_finding(
                        record=record,
                        title=f"Server Version Disclosure ({vh})",
                        description=f"The '{vh}' header leaks specific server technology version numbers. This information can help attackers identify known vulnerabilities in your stack.",
                        severity="Low",
                        evidence=f"{vh.__title__()}: {header_val}"
                    )
                    
        # 4. Insecure Cookies
        # Note: In HTTPX, response.cookies is a cookie jar.
        # However, HttpUtils.send_request_recorded stores raw set-cookie headers.
        # Let's parse 'set-cookie' if it exists.
        set_cookies = record.response_headers.get("Set-Cookie", "")
        # Note: If there are multiple Set-Cookie headers, httpx usually joins them with commas or returns a list.
        # We will do a generic check on the raw Set-Cookie string.
        if set_cookies:
            # We can just check the string contents as a basic heuristic
            cookies_list = set_cookies.split(',') if isinstance(set_cookies, str) else set_cookies
            if isinstance(cookies_list, str):
                cookies_list = [cookies_list]
                
            for cookie in cookies_list:
                cookie_lower = cookie.lower()
                if "secure" not in cookie_lower or "httponly" not in cookie_lower:
                    self.add_finding(
                        record=record,
                        title="Insecure Cookie Configuration",
                        description="A session cookie was set without the 'Secure' and/or 'HttpOnly' flags. This increases the risk of cookie theft via XSS or Man-in-the-Middle attacks.",
                        severity="Low",
                        evidence=f"Set-Cookie: {cookie.strip()}"
                    )
                    # Once flagged, no need to flag every single cookie
                    break

        return self.results
