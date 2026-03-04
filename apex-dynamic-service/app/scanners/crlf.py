from typing import List, Dict, Any
import urllib.parse
import copy

from app.scanners.base import BaseScanner
from app.scanner_utils.http import HttpUtils
from app.scanner_utils.payloads import PayloadLibrary
from app.scanner_utils.detection import DetectionUtils

class CrlfScanner(BaseScanner):
    @property
    def scan_id(self) -> str:
        return "APEX-CRLF"

    @property
    def name(self) -> str:
        return "CRLF Injection Scanner"

    @property
    def category(self) -> str:
        return "Improper Input Handling (HTTP Response Splitting)"

    @property
    def description(self) -> str:
        return "Detects Carriage Return Line Feed (CRLF) injection vulnerabilities, which can lead to HTTP Response Splitting, XSS, or Cache Poisoning."

    def _check_crlf_headers(self, record):
        """Checks if the injected CRLF header was reflected in the response headers."""
        if not record or not record.response_headers:
            return False
        
        # We explicitly look for the 'CRLF-Test' header or value we injected
        for k, v in record.response_headers.items():
            if DetectionUtils.CRLF_INDICATOR.lower() in k.lower():
                return True
        return False

    def run(self, endpoint: str, method: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.results = []
        target_url = f"{self.context.target_url.rstrip('/')}{endpoint}"
        parsed_url = urllib.parse.urlparse(target_url)

        # 1. URL Path Injection
        for payload in PayloadLibrary.CRLF_PAYLOADS:
            injected_path_url = f"{target_url}/{payload}"
            
            record = HttpUtils.send_request_recorded(
                method=method,
                url=injected_path_url,
                auth=self.context.auth
            )
            
            if self._check_crlf_headers(record):
                self.add_finding(
                    record=record,
                    title="CRLF Injection (URL Path)",
                    description="The application reflects user input from the URL path directly into HTTP headers, allowing HTTP Response Splitting.",
                    severity="High",
                    evidence=f"Reflected custom header: {DetectionUtils.CRLF_INDICATOR}"
                )
                break  # Don't flood with duplicate path findings

        # 2. Query Parameter Injection
        if parsed_url.query:
            parsed_query = urllib.parse.parse_qs(parsed_url.query)
            for key, values in parsed_query.items():
                vuln_found = False
                for payload in PayloadLibrary.CRLF_PAYLOADS:
                    temp_query = copy.deepcopy(parsed_query)
                    temp_query[key] = [payload]
                    new_query_string = urllib.parse.urlencode(temp_query, doseq=True)
                    injected_query_url = target_url.split('?')[0] + '?' + new_query_string
                    
                    record = HttpUtils.send_request_recorded(
                        method=method,
                        url=injected_query_url,
                        auth=self.context.auth
                    )
                    
                    if self._check_crlf_headers(record):
                        self.add_finding(
                            record=record,
                            title="CRLF Injection (Query Parameter)",
                            description=f"The query parameter '{key}' is reflected into HTTP headers without sanitization.",
                            severity="High",
                            evidence=f"Reflected custom header: {DetectionUtils.CRLF_INDICATOR}\nInjected via: {key}={payload}"
                        )
                        vuln_found = True
                        break
                if vuln_found:
                    continue

        # 3. Request Body Injection
        if method.upper() in ["POST", "PUT", "PATCH"]:
            example_body = params.get("example", {})
            if isinstance(example_body, dict):
                for key in example_body.keys():
                    vuln_found = False
                    for payload in PayloadLibrary.CRLF_PAYLOADS:
                        temp_body = copy.deepcopy(example_body)
                        temp_body[key] = payload
                        
                        record = HttpUtils.send_request_recorded(
                            method=method,
                            url=target_url,
                            json=temp_body,
                            auth=self.context.auth
                        )
                        
                        if self._check_crlf_headers(record):
                            self.add_finding(
                                record=record,
                                title="CRLF Injection (Request Body)",
                                description=f"The JSON body parameter '{key}' is reflected into HTTP headers without sanitization.",
                                severity="High",
                                evidence=f"Reflected custom header: {DetectionUtils.CRLF_INDICATOR}\nInjected via body key: {key}"
                            )
                            vuln_found = True
                            break
                    if vuln_found:
                        continue

        return self.results
