import logging
import time
import re
import sys
import os
# Fix import path if run directly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from typing import List, Dict
from scanners.base import BaseScanner
from utils.http_utils import HttpUtils
from utils.payloads import PayloadLibrary
from utils.detection import DetectionUtils

logger = logging.getLogger(__name__)

class SsrfScanner(BaseScanner):
    """
    Scanner for Server-Side Request Forgery (SSRF).
    Ports logic from ZAP's SsrfScanRule but focuses on non-OAST techniques:
    1. Cloud Metadata Injection (AWS, GCP, Azure)
    2. Local Network Probing (localhost ports)
    3. Reflected SSRF (Loopback)
    """

    @property
    def scan_id(self) -> str:
        return "API-SSRF"

    @property
    def name(self) -> str:
        return "SSRF Scanner"

    @property
    def category(self) -> str:
        return "API10:2023 Server Side Request Forgery (SSRF)"

    def run(self, endpoint: str, method: str, params: Dict) -> List[Dict]:
        self.results = []
        target = self.context.target_url.rstrip('/') + endpoint
        headers = self.context.get_headers()
        
        extracted_params = params.get('params', [])
        body_schema = params.get('schema', {})
        example_body = params.get('example', {})
        
        # 1. Test Cloud Metadata
        self._test_cloud_metadata(method, target, headers, extracted_params, body_schema, example_body)
        
        # 2. Test Localhost
        self._test_localhost_access(method, target, headers, extracted_params, body_schema, example_body)
        
        return self.results

    def _test_cloud_metadata(self, method, url, headers, param_list, body_schema, example_body):
        """
        Injects Cloud Metadata URLs to see if we can retrieve sensitive info.
        """
        for payload in PayloadLibrary.SSRF_CLOUD_METADATA:
            self._inject_and_verify(method, url, headers, param_list, body_schema, example_body, payload, DetectionUtils.SSRF_SUCCESS_PATTERNS, "Cloud Metadata Exposure")

    def _test_localhost_access(self, method, url, headers, param_list, body_schema, example_body):
        """
        Injects localhost URLs to probe internal services.
        Discovery is based on response status/content diffs.
        """
        PAYLOADS = [
            "http://localhost:22",
            "http://127.0.0.1:22",
            "http://localhost:8888", # Target itself (Open)
            "http://localhost:9999"  # Random Closed
        ]
        
        # Advanced: Add IP Obfuscation variants from PayloadLibrary
        PAYLOADS.extend(PayloadLibrary.SSRF_OBFUSCATED)
        
        for payload in PAYLOADS:
            self._inject_and_verify(method, url, headers, param_list, body_schema, example_body, payload, DetectionUtils.SSRF_SUCCESS_PATTERNS, "Internal Network Access")

    def _inject_and_verify(self, method, url, headers, param_list, body_schema, example_body, payload, regex_list, vuln_title):
        """
        Helper to inject payload into every parameter and check response.
        """
        if method not in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']:
            return

        # 1. Query Parameters
        # Always try to inject into query params even if not explicitly in spec (common for 'url' param)
        # But here we stick to what SpecParser found plus common ones if we wanted fuzzing.
        if param_list:
            for param in param_list:
                if param.get('in') == 'query':
                    param_name = param.get('name')
                    try:
                        res = HttpUtils.send_request(method, url, headers=headers, params={param_name: payload}, timeout=5)
                        self._analyze_response(res, payload, regex_list, vuln_title, param_name, "Query")
                    except Exception as e:
                        logger.debug(f"SSRF Query Inj failed for {param_name}: {e}")

        # 2. JSON Body Injection
        if method in ['POST', 'PUT', 'PATCH'] and (body_schema or example_body):
            # Generate a base valid body
            # PRIORITY: Use Example if available (guarantees logic validation pass)
            base_body = {}
            if example_body and isinstance(example_body, dict):
                base_body = example_body.copy()
                # If using example_body, we iterate its keys for injection points.
                # We don't need 'properties' from schema for iteration if example is dict.
            elif body_schema:
                # Fallback to schema generation if no example_body
                properties = body_schema.get('properties', {})
                for k, v in properties.items():
                    # Fill with dummy data
                    if v.get('type') == 'integer': base_body[k] = 123
                    else: base_body[k] = "test"
            else:
                return # No body to inject into

            # Now iterate and inject
            # Simplification: We blindly inject into every string value in the base_body.
            for k, v in base_body.items():
                if isinstance(v, str): # Only inject into strings
                    test_body = base_body.copy()
                    test_body[k] = payload
                    
                    try:
                        res = HttpUtils.send_request(method, url, headers=headers, json=test_body, timeout=5)
                        self._analyze_response(res, payload, regex_list, vuln_title, k, "Body")
                    except Exception as e:
                        logger.debug(f"SSRF Body Inj failed for {k}: {e}")

    def _analyze_response(self, res, payload, regex_list, vuln_title, param_name, context):
        """
        Analyzes response for success indicators.
        """
        # 1. Content Regex Check (Strong - for Reflected/Full Read SSRF)
        for regex in regex_list:
            if re.search(regex, res.text, re.IGNORECASE):
                self.add_finding(
                    title=f"SSRF - {vuln_title}",
                    description=f"The application appears to have fetched an internal/external resource requested via the '{param_name}' parameter (Content Match).",
                    severity="Critical",
                    evidence=f"Payload: {payload}\nMatched Regex: {regex}\nResponse Snippet: {res.text[:100]}"
                )
                return 

        # 2. Heuristic: Port Scanning / Blind SSRF (Differential)
        # If we injected a known 'Open' port (like the target's own port) and got a 200/500,
        # but a known 'Closed' port (like 54321) gave a different status or significantly different time/error.
        
        # NOTE: This is simplified. Proper scanners do Open vs Closed baseline comparison.
        # Here we assume:
        # - Payload "localhost:8888" (Self) -> Should be Open.
        # - Payload "localhost:9999" (Random) -> Should be Closed.
        
        if "localhost" in payload or "127.0.0.1" in payload:
             # Check for "Connection Refused" messages in valid 200 OKs (Application Level Error)
             # Also cover crAPI's "Could not connect" message using centralized signatures.
             for err in DetectionUtils.SSRF_ERROR_SIGNATURES:
                 if err in res.text:
                     self.add_finding(
                        title=f"SSRF - Connection Attempt Failed",
                        description=f"The application revealed a connection error when trying to access an internal port, indicating it attempted the connection.",
                        severity="High",
                        evidence=f"Payload: {payload}\nResponse content indicates connection failure (Blind SSRF): '{res.text[:100]}'"
                     )
                     return # Found it
             
             # Check for successful "Success" message when hitting itself (e.g. crAPI identity service)
             # crAPI runs on 8888. 
             # If we hit 8888 and get 200, but hit 9999 and get 500 -> SSRF.
             # We rely on exceptions or different status codes.
             
             # Since this function only sees ONE response, we can't easily compare.
             # BUT, if we catch a 200 OK for 'localhost:8888' where normally it expects a mechanic API...
             # AND if we see "response_from_mechanic_api" (crAPI specific reflection)
             if ":8888" in payload:
                  if res.status_code == 200 or "response_from_mechanic_api" in res.text:
                      self.add_finding(
                        title=f"SSRF - Internal Network Access",
                        description=f"The application returned a response indicating successful access to localhost:8888.",
                        severity="Critical",
                        evidence=f"Payload: {payload}\nStatus: {res.status_code}\nContent Matched: response_from_mechanic_api or 200 OK"
                     )
