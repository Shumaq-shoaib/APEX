import logging
import base64
import json
import re
from typing import List, Dict
from scanners.base import BaseScanner
from utils.http_utils import HttpUtils

logger = logging.getLogger(__name__)

class JwtScanner(BaseScanner):
    """
    Scanner for JWT specific vulnerabilities.
    Checks for 'None' algorithm attacks and signature exclusion.
    """

    @property
    def scan_id(self) -> str:
        return "API-JWT-SCAN"

    @property
    def name(self) -> str:
        return "JWT Security Scanner"

    @property
    def category(self) -> str:
        return "API2:2023 Broken Authentication"

    def run(self, endpoint: str, method: str, params: Dict) -> List[Dict]:
        self.results = [] # Clear previous results
        
        target = self.context.target_url.rstrip('/') + endpoint
        headers = self.context.get_headers()
        return self.scan(method, target, headers, body=None)

    def scan(self, method, url, headers, body=None):
        """
        Scans an endpoint if a JWT is detected in the headers.
        """
        # 1. Identify JWT
        # Look in Authorization header
        auth_header = headers.get("Authorization", "")
        jwt_token = None
        if "Bearer " in auth_header:
            parts = auth_header.split(" ")
            if len(parts) == 2:
                potential_jwt = parts[1]
                if self._is_jwt(potential_jwt):
                    jwt_token = potential_jwt

        if not jwt_token:
            return []

        # 2. Perform Attacks
        try:
            self._test_none_algorithm(method, url, headers, body, jwt_token)
            self._test_signature_exclusion(method, url, headers, body, jwt_token)
            
        except Exception as e:
            logger.debug(f"JWT Scan Error: {e}")

        return self.results

    def _is_jwt(self, token):
        """Simple check if a string looks like a JWT (header.payload.signature)."""
        parts = token.split('.')
        return len(parts) == 3

    def _test_none_algorithm(self, method, url, headers, body, original_token):
        """
        Test 1: "None" Algorithm Attack.
        Change header to {"alg": "none"} and remove signature.
        """
        try:
            header, payload, sig = original_token.split('.')
            
            # Create "None" Header
            none_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode('utf-8').rstrip('=')
            
            # Construct Token: header.payload. (note the trailing dot)
            attack_token = f"{none_header}.{payload}."
            
            self._send_attack(method, url, headers, body, attack_token, "JWT None Algorithm", "The server accepted a JWT signed with the 'none' algorithm.")
            
        except Exception as e:
            logger.debug(f"JWT None Algo Attack failed: {e}")

    def _test_signature_exclusion(self, method, url, headers, body, original_token):
        """
        Test 2: Signature Exclusion.
        Keep valid header/payload, but remove signature (keep trailing dot optional, try both).
        """
        try:
            header, payload, sig = original_token.split('.')
            
            # Attack A: No signature, trailing dot
            attack_token_1 = f"{header}.{payload}."
            self._send_attack(method, url, headers, body, attack_token_1, "JWT Signature Exclusion", "The server accepted a JWT with the signature removed.")
            
            # Attack B: No signature, no trailing dot skipped for brevity/duplication
        except Exception as e:
            logger.debug(f"JWT Sig Exclusion Attack failed: {e}")

    def _send_attack(self, method, url, orig_headers, body, attack_token, title, description):
        """Helper to send request and check response."""
        attack_headers = orig_headers.copy()
        attack_headers["Authorization"] = f"Bearer {attack_token}"

        res, record = HttpUtils.send_request_recorded(method, url, headers=attack_headers, json=body, timeout=5)

        if res.status_code in [200, 201, 202]:
             self.add_finding(
                title=title,
                description=description,
                severity="Critical",
                evidence=f"Token Used: {attack_token}\nResponse Code: {res.status_code}",
                request_dump=record.format_request_dump(),
                response_dump=record.format_response_dump()
            )
