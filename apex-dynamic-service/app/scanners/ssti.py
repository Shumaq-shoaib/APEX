from typing import List, Dict, Any
import urllib.parse
import copy

from app.scanners.base import BaseScanner
from app.scanner_utils.http import HttpUtils
from app.scanner_utils.payloads import PayloadLibrary
from app.scanner_utils.detection import DetectionUtils

class SstiScanner(BaseScanner):
    @property
    def scan_id(self) -> str:
        return "APEX-SSTI"

    @property
    def name(self) -> str:
        return "Server-Side Template Injection (SSTI) Scanner"

    @property
    def category(self) -> str:
        return "API8:2023 Security Misconfiguration (Injection)"

    @property
    def description(self) -> str:
        return "Detects Server-Side Template Injection (SSTI) by injecting template expressions (e.g., {{7*7}}) and checking for computed execution results (e.g., 49)."

    def _check_ssti_execution(self, record):
        """Checks if the injected SSTI payload was executed."""
        if not record or not record.response_body:
            return False
            
        # Check if the evaluation result of the template expression is in the body
        return DetectionUtils.check_content_patterns(record.response_body, DetectionUtils.SSTI_RESULT_PATTERNS)

    def run(self, endpoint: str, method: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.results = []
        target_url = f"{self.context.target_url.rstrip('/')}{endpoint}"
        parsed_url = urllib.parse.urlparse(target_url)

        # 1. Query Parameter Injection
        if parsed_url.query:
            parsed_query = urllib.parse.parse_qs(parsed_url.query)
            for key, values in parsed_query.items():
                for payload in PayloadLibrary.SSTI_PAYLOADS:
                    temp_query = copy.deepcopy(parsed_query)
                    temp_query[key] = [payload]
                    new_query_string = urllib.parse.urlencode(temp_query, doseq=True)
                    injected_query_url = target_url.split('?')[0] + '?' + new_query_string
                    
                    record = HttpUtils.send_request_recorded(
                        method=method,
                        url=injected_query_url,
                        auth=self.context.auth
                    )
                    
                    matched_pattern = self._check_ssti_execution(record)
                    if matched_pattern or (payload in ["{{config}}", "${class.forName('java.lang.Runtime')}"] and ("secret" in str(record.response_body).lower() or "java.lang" in str(record.response_body))):
                        self.add_finding(
                            record=record,
                            title="Server-Side Template Injection (SSTI)",
                            description=f"The query parameter '{key}' is passed into a template engine, leading to arbitrary code execution.",
                            severity="Critical",
                            evidence=f"Injected template payload: {payload}\nExecution result found in response."
                        )
                        return self.results # Stop on first critical finding per endpoint

        # 2. Request Body Injection
        if method.upper() in ["POST", "PUT", "PATCH"]:
            example_body = params.get("example", {})
            if isinstance(example_body, dict):
                for key in example_body.keys():
                    for payload in PayloadLibrary.SSTI_PAYLOADS:
                        temp_body = copy.deepcopy(example_body)
                        temp_body[key] = payload
                        
                        record = HttpUtils.send_request_recorded(
                            method=method,
                            url=target_url,
                            json=temp_body,
                            auth=self.context.auth
                        )
                        
                        matched_pattern = self._check_ssti_execution(record)
                        if matched_pattern or (payload in ["{{config}}", "${class.forName('java.lang.Runtime')}"] and ("secret" in str(record.response_body).lower() or "java.lang" in str(record.response_body))):
                            self.add_finding(
                                record=record,
                                title="Server-Side Template Injection (SSTI)",
                                description=f"The JSON body parameter '{key}' is passed into a template engine, leading to arbitrary code execution.",
                                severity="Critical",
                                evidence=f"Injected template payload: {payload}\nExecution result found in response."
                            )
                            return self.results

        return self.results
