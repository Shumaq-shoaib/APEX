import hashlib
import re
from typing import List, Dict
from scanners.base import BaseScanner
from utils.http_utils import HttpUtils
from utils.payloads import PayloadLibrary

class UsernameIdorScanner(BaseScanner):
    """
    Simulates ZAP's UsernameIdorScanRule (Passive).
    Checks for unexpected leakage of username hashes in responses.
    """

    @property
    def scan_id(self) -> str:
        return "API-IDOR-PASSIVE"

    @property
    def name(self) -> str:
        return "Username Hash Disclosure (IDOR)"

    @property
    def category(self) -> str:
        return "API1:2023 Broken Object Level Authorization"

    def run(self, endpoint: str, method: str, params: Dict) -> List[Dict]:
        # Passive check: We reusing the context's target. 
        # In a real ZAP flow, this runs on *every* response. 
        # Here we will make a fresh request to the endpoint to analyze its response.
        
        target = self.context.target_url.rstrip('/') + endpoint
        headers = self.context.get_headers()
        
        try:
            res, record = HttpUtils.send_request_recorded(method, target, headers=headers, timeout=5)
            content = res.text
            
            for user in PayloadLibrary.IDOR_DEFAULT_USERS:
                hashes = {
                    "MD5": hashlib.md5(user.encode()).hexdigest(),
                    "SHA1": hashlib.sha1(user.encode()).hexdigest(),
                    "SHA256": hashlib.sha256(user.encode()).hexdigest()
                }
                
                for alg, hash_val in hashes.items():
                    if hash_val in content:
                        self.add_finding(
                            title=f"Username Hash Disclosure ({alg})",
                            description=f"The {alg} hash of the username '{user}' was found in the response.",
                            severity="Info",
                            evidence=f"Hash: {hash_val}",
                            request_dump=record.format_request_dump(),
                            response_dump=record.format_response_dump()
                        )
                        
        except Exception as e:
            import logging
            logging.debug(f"IDOR check failed for {endpoint}: {e}")
            
        return self.results
