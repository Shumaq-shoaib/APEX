from typing import List, Dict, Any
from copy import deepcopy

from app.scanners.base import BaseScanner
from app.scanner_utils.http import HttpUtils

class BrokenAuthScanner(BaseScanner):
    @property
    def scan_id(self) -> str:
        return "APEX-BROKEN-AUTH"

    @property
    def name(self) -> str:
        return "Broken Authentication Scanner"

    @property
    def category(self) -> str:
        return "API2:2023 Broken Authentication"

    @property
    def description(self) -> str:
        return "Detects endpoints that fail to properly enforce authentication by testing them with missing or invalid tokens."

    def run(self, endpoint: str, method: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.results = []
        target_url = f"{self.context.target_url.rstrip('/')}{endpoint}"

        # If we have no authentication context, we cannot test if authentication is *broken*
        # because we don't know what a successful authenticated response looks like.
        if not self.context.auth or not self.context.auth.token:
            return self.results

        # 1. Baseline Request (Authenticated)
        request_kwargs = {
            "method": method,
            "url": target_url,
            "auth": self.context.auth
        }
        
        # Add body if needed (using example params if present)
        example_body = params.get("example")
        if example_body and method.upper() in ["POST", "PUT", "PATCH"]:
            request_kwargs["json"] = example_body

        baseline_record = HttpUtils.send_request_recorded(**request_kwargs)
        
        if not baseline_record or not str(baseline_record.status_code).startswith("2"):
            # Only test endpoints that actually succeed with our known good auth
            return self.results

        baseline_length = len(baseline_record.response_body) if baseline_record.response_body else 0

        # Helper to compare responses
        def _is_unauthorized_access(record) -> bool:
            if not record:
                return False
            if str(record.status_code).startswith("2"):
                # If length is roughly the same, it's definitely returning the same data
                test_length = len(record.response_body) if record.response_body else 0
                if abs(baseline_length - test_length) < 100:
                    return True
            return False

        vuln_found = False

        # 2. Test Missing Authentication (No Token)
        no_auth_kwargs = deepcopy(request_kwargs)
        no_auth_kwargs["auth"] = None
        
        no_auth_record = HttpUtils.send_request_recorded(**no_auth_kwargs)
        
        if _is_unauthorized_access(no_auth_record):
            self.add_finding(
                record=no_auth_record,
                title="Broken Authentication (Missing Token Allowed)",
                description="The endpoint accepts requests without any authentication token and returns the same successful response as an authenticated user.",
                severity="Critical",
                evidence=f"Baseline Status: {baseline_record.status_code}\nUnauthenticated Status: {no_auth_record.status_code}\nTokens were completely stripped from the request."
            )
            vuln_found = True

        # 3. Test Invalid Authentication (Tampered Token)
        if not vuln_found:
            invalid_auth = deepcopy(self.context.auth)
            # Tamper the token (e.g., append "INVALID")
            if hasattr(invalid_auth, 'token') and invalid_auth.token:
                invalid_auth.token = invalid_auth.token[:-5] + "INVLD"
            
            invalid_auth_kwargs = deepcopy(request_kwargs)
            invalid_auth_kwargs["auth"] = invalid_auth
            
            invalid_auth_record = HttpUtils.send_request_recorded(**invalid_auth_kwargs)
            
            if _is_unauthorized_access(invalid_auth_record):
                self.add_finding(
                    record=invalid_auth_record,
                    title="Broken Authentication (Invalid Token Accepted)",
                    description="The endpoint accepts an invalid, tampered authentication token and returns the same successful response as a valid token.",
                    severity="Critical",
                    evidence=f"Baseline Status: {baseline_record.status_code}\nTampered Token Status: {invalid_auth_record.status_code}\nThe token signature or integrity is not being verified."
                )

        return self.results
