from typing import List, Dict
from scanners.base import BaseScanner
from utils.http_utils import HttpUtils

class SecurityHeadersScanner(BaseScanner):
    """
    Basic scanner to check for missing security headers.
    Maps to basic ZAP passive scan rules.
    """
    
    @property
    def scan_id(self) -> str:
        return "API-SEC-HEADERS"

    @property
    def name(self) -> str:
        return "Missing Security Headers"

    @property
    def category(self) -> str:
        return "API7:2023 Security Misconfiguration"

    def run(self, endpoint: str, method: str, params: Dict) -> List[Dict]:
        self.results = []
        target = self.context.target_url.rstrip('/') + endpoint
        headers = self.context.get_headers()
        
        try:
            # We just need one request to check headers
            response = HttpUtils.send_request(method, target, headers=headers, timeout=5)
            
            # Check for standard headers
            required_headers = [
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "Strict-Transport-Security"
            ]
            
            for h in required_headers:
                if h not in response.headers:
                    self.add_finding(
                        title=f"Missing {h} Header",
                        description=f"The response is missing the {h} security header.",
                        severity="Low",
                        evidence=f"Headers received: {list(response.headers.keys())}"
                    )
            
            return self.results
            
        except Exception as e:
            import logging
            logging.debug(f"Error checking security headers: {e}")
            
        return []
