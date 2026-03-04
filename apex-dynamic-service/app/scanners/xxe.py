import logging
from typing import List, Dict
from app.scanners.base import BaseScanner
from app.scanner_utils.payloads import PayloadLibrary
from app.scanner_utils.detection import DetectionUtils
from app.scanner_utils.http import HttpUtils

logger = logging.getLogger(__name__)

class XxeScanner(BaseScanner):
    """
    Scanner for XML External Entity (XXE) vulnerabilities.
    Simulates ZAP's XxeScanRule.
    """

    @property
    def scan_id(self) -> str:
        return "APEX-XXE"

    @property
    def name(self) -> str:
        return "XML External Entity (XXE)"

    @property
    def category(self) -> str:
        return "API8:2023 Injection"

    def run(self, endpoint: str, method: str, params: Dict) -> List[Dict]:
        self.results = []
        target = self.context.target_url.rstrip('/') + endpoint
        headers = self.context.get_headers()
        
        # Only relevant for POST/PUT/PATCH usually
        if method not in ['POST', 'PUT', 'PATCH']:
            return []
            
        # 1. Check if endpoint accepts XML (by spec) or we can try to force it
        # Strategy: Try to inject XML body regardless of spec saying 'application/json' 
        # because some parsers switch based on Content-Type header (Format Confusion).
        
        self._test_xxe(method, target, headers)

        return self.results

    def _test_xxe(self, method, target, headers):
        """Inject XXE payloads into body."""
        
        # We try both Unix and Windows targets for each payload template
        # We try both Unix and Windows targets for each payload template
        targets = PayloadLibrary.XXE_TARGETS
        
        # Helper to send attack
        def send_attack(payload_body):
             try:
                attack_headers = headers.copy()
                attack_headers['Content-Type'] = 'application/xml'
                res = HttpUtils.send_request(method, target, headers=attack_headers, data=payload_body, timeout=5)
                return res
             except Exception as e:
                logger.debug(f"XXE check failed for {target}: {e}")
                return None

        for template in PayloadLibrary.XXE_PAYLOADS:
            # Case 1: File Disclosure (needs {target})
            if "{target}" in template:
                for os_type, file_target in targets.items():
                    payload = template.format(target=file_target)
                    res = send_attack(payload)
                    if res:
                        # Check for pattern matches (file content leakage)
                        if os_type == 'unix':
                             if "root:x:0:0" in res.text or "root:*:0:0" in res.text:
                                 self.add_finding(
                                     title="XXE (Unix File Disclosure)",
                                     description="The application processed an XML External Entity and leaked /etc/passwd.",
                                     severity="Critical",
                                     evidence=f"Payload: {payload}\nSnippet: {res.text[:100]}"
                                 )
                                 return
                        elif os_type == 'windows':
                             if "[fonts]" in res.text or "[extensions]" in res.text:
                                  self.add_finding(
                                     title="XXE (Windows File Disclosure)",
                                     description="The application processed an XML External Entity and leaked C:/Windows/win.ini.",
                                     severity="Critical",
                                     evidence=f"Payload: {payload}\nSnippet: {res.text[:100]}"
                                 )
                                  return

            # Case 2: OAST (needs {oast_host})
            elif "{oast_host}" in template:
                # Use a dummy host or configured one. 
                # Ideally, this should come from config. For now using localhost or explicit callback.
                oast_host = "127.0.0.1" 
                payload = template.format(oast_host=oast_host)
                res = send_attack(payload)
                # OAST verification requires a separate callback check, usually asynchronous.
                # We can't easily verify it here without a callback server.
                # We just log it as attempted.
                
            # Case 3: DoS / Logic (no placeholders)
            else:
                # Be careful with DoS. Maybe only send if attack strength is high?
                # For now, we send it once.
                payload = template
                res = send_attack(payload)
                # Verification for DoS is ... if it times out or errors? 
                # We won't verify DoS automatically to avoid taking down service.


