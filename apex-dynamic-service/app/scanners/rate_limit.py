from typing import List, Dict, Any
import random
import string
import copy
import asyncio

from app.scanners.base import BaseScanner
from app.scanner_utils.http import HttpUtils
from app.scanner_utils.payloads import PayloadLibrary
from app.scanner_utils.detection import DetectionUtils

class RateLimitScanner(BaseScanner):
    @property
    def scan_id(self) -> str:
        return "APEX-RATE-LIMIT"

    @property
    def name(self) -> str:
        return "Rate Limiting & Brute Force Scanner"

    @property
    def category(self) -> str:
        return "API4:2023 Unrestricted Resource Consumption"

    @property
    def description(self) -> str:
        return "Detects missing rate limits on sensitive endpoints (e.g., authentication, OTPs) by automating a burst of requests."

    def _generate_burst_values(self, original_value: Any, count: int = 50) -> List[Any]:
        """Generate a list of random values to attempt brute force."""
        values = []
        if isinstance(original_value, int):
            # Generate random integers of similar length
            length = len(str(original_value))
            for _ in range(count):
                values.append(random.randint(10**(length-1) if length > 1 else 0, (10**length) - 1))
        else:
            # Generate random strings
            length = len(str(original_value))
            if length == 0:
                length = 8
            for _ in range(count):
                values.append(''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length)))
        return values

    def _is_rate_limited(self, record) -> bool:
        """Check if the response indicates rate limiting."""
        if not record:
            return False
            
        # 429 Too Many Requests is the standard HTTP status for rate limiting
        if record.status_code == 429:
            return True
            
        # Check body for rate limit signals if it's a 4xx error
        if record.response_body and str(record.status_code).startswith('4'):
            body_text = record.response_body.lower()
            for signal in DetectionUtils.RATE_LIMIT_SIGNALS:
                if signal.lower() in body_text:
                    return True
                    
        return False

    def run(self, endpoint: str, method: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.results = []
        
        # We primarily care about POST/PUT for rate limiting (e.g., login, password reset)
        if method.upper() not in ["POST", "PUT", "PATCH"]:
            return self.results
            
        example_body = params.get("example", {})
        if not isinstance(example_body, dict) or not example_body:
            return self.results

        target_url = f"{self.context.target_url.rstrip('/')}{endpoint}"
        
        # 1. Identify Sensitive Parameter
        sensitive_param = None
        for key in example_body.keys():
            if any(s in key.lower() for s in PayloadLibrary.RATE_LIMIT_SENSITIVE_PARAMS):
                sensitive_param = key
                break
                
        if not sensitive_param:
            return self.results

        # 2. Generate payloads
        burst_values = self._generate_burst_values(example_body[sensitive_param], count=50)
        
        # 3. Send Burst (we do it sequentially here to avoid overwhelming connection pools, 
        # but fast enough to trigger basic application-level rate limits)
        rate_limit_triggered = False
        last_record = None
        
        for val in burst_values:
            temp_body = copy.deepcopy(example_body)
            temp_body[sensitive_param] = val
            
            # Intentionally remove auth token if we are testing auth brute force
            # But if it requires auth, we keep it. 
            auth_to_use = self.context.auth
            
            record = HttpUtils.send_request_recorded(
                method=method,
                url=target_url,
                json=temp_body,
                auth=auth_to_use
            )
            
            if not record:
                continue
                
            last_record = record
            
            if self._is_rate_limited(record):
                rate_limit_triggered = True
                break
                
        if not rate_limit_triggered and last_record:
            self.add_finding(
                record=last_record,
                title="Missing Rate Limiting (Brute Force Risk)",
                description=f"Sent 50 rapid requests modifying the sensitive parameter '{sensitive_param}' without triggering any rate limit (HTTP 429) or CAPTCHA.",
                severity="High",
                evidence=f"Last Status Code: {last_record.status_code}\nMissing 429 Too Many Requests response."
            )

        return self.results
