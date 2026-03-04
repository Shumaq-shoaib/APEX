from typing import List, Dict, Any
import urllib.parse
import copy

from app.scanners.base import BaseScanner
from app.scanner_utils.http import HttpUtils
from app.scanner_utils.payloads import PayloadLibrary
from app.scanner_utils.detection import DetectionUtils

class XssScanner(BaseScanner):
    @property
    def scan_id(self) -> str:
        return "APEX-XSS"

    @property
    def name(self) -> str:
        return "Cross-Site Scripting (XSS) Scanner"

    @property
    def category(self) -> str:
        return "API8:2023 Security Misconfiguration (Injection)"

    @property
    def description(self) -> str:
        return "Detects reflected XSS vulnerabilities by injecting malicious scripts into headers, query parameters, URI paths, and request bodies."

    def _check_xss_reflection(self, record):
        """Checks if the injected XSS payload was reflected exactly, or if reflection patterns matched."""
        if not record or not record.response_body:
            return False
            
        return DetectionUtils.check_content_patterns(record.response_body, DetectionUtils.XSS_REFLECTION_PATTERNS)

    def run(self, endpoint: str, method: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.results = []
        target_url = f"{self.context.target_url.rstrip('/')}{endpoint}"
        parsed_url = urllib.parse.urlparse(target_url)

        # Baseline request to check security headers
        baseline = HttpUtils.send_request_recorded(
            method=method, url=target_url, auth=self.context.auth
        )
        
        has_csp = False
        has_xcto = False
        
        if baseline and baseline.response_headers:
            headers_lower = {k.lower(): v.lower() for k, v in baseline.response_headers.items()}
            has_csp = "content-security-policy" in headers_lower
            has_xcto = "nosniff" in headers_lower.get("x-content-type-options", "")

        def _report(record, vector, payload):
            # Calculate impact
            # Reflected XSS without CSP/nosniff is High, else Medium
            severity = "High" if not (has_csp and has_xcto) else "Medium"
            desc_extra = "" if not has_csp else " Note: Contextual defenses (CSP) are present, which may mitigate exploitation."
            
            self.add_finding(
                record=record,
                title="Cross-Site Scripting (Reflected)",
                description=f"Injected XSS payload via {vector} was reflected in the HTTP response.{desc_extra}",
                severity=severity,
                evidence=f"Payload Injected: {payload}\nVector: {vector}"
            )

        # 1. URL Path Injection
        for payload in PayloadLibrary.XSS_PAYLOADS:
            injected_path_url = f"{target_url}/{urllib.parse.quote(payload)}"
            
            record = HttpUtils.send_request_recorded(
                method=method, url=injected_path_url, auth=self.context.auth
            )
            
            if self._check_xss_reflection(record):
                _report(record, "URL Path", payload)
                break  # Find one per endpoint

        # 2. Query Parameter Injection
        if parsed_url.query:
            parsed_query = urllib.parse.parse_qs(parsed_url.query)
            for key, values in parsed_query.items():
                vuln_found = False
                for payload in PayloadLibrary.XSS_PAYLOADS:
                    temp_query = copy.deepcopy(parsed_query)
                    temp_query[key] = [payload]
                    new_query_string = urllib.parse.urlencode(temp_query, doseq=True)
                    injected_query_url = target_url.split('?')[0] + '?' + new_query_string
                    
                    record = HttpUtils.send_request_recorded(
                        method=method, url=injected_query_url, auth=self.context.auth
                    )
                    
                    if self._check_xss_reflection(record):
                        _report(record, f"Query Parameter '{key}'", payload)
                        vuln_found = True
                        break
                if vuln_found:
                    continue

        # 3. HTTP Header Injection
        for header_name in ["Referer", "User-Agent", "X-Forwarded-For"]:
            for payload in PayloadLibrary.XSS_PAYLOADS:
                headers = {header_name: payload}
                record = HttpUtils.send_request_recorded(
                    method=method, url=target_url, headers=headers, auth=self.context.auth
                )
                
                if self._check_xss_reflection(record):
                    _report(record, f"HTTP Header '{header_name}'", payload)
                    break

        # 4. Request Body Injection
        if method.upper() in ["POST", "PUT", "PATCH"]:
            example_body = params.get("example", {})
            if isinstance(example_body, dict):
                for key in example_body.keys():
                    vuln_found = False
                    for payload in PayloadLibrary.XSS_PAYLOADS:
                        temp_body = copy.deepcopy(example_body)
                        temp_body[key] = payload
                        
                        record = HttpUtils.send_request_recorded(
                            method=method, url=target_url, json=temp_body, auth=self.context.auth
                        )
                        
                        if self._check_xss_reflection(record):
                            _report(record, f"JSON Body Key '{key}'", payload)
                            vuln_found = True
                            break
                    if vuln_found:
                        continue

        return self.results
