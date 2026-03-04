import re
import time
import logging
from typing import List, Dict
from app.scanners.base import BaseScanner
from app.scanner_utils.payloads import PayloadLibrary
from app.scanner_utils.detection import DetectionUtils
from app.scanner_utils.http import HttpUtils

logger = logging.getLogger(__name__)

class CommandInjectionScanner(BaseScanner):
    """
    Scanner for OS Command Injection.
    Simulates ZAP's CommandInjectionScanRule.
    Uses Content-Based and Time-Based detection.
    """

    @property
    def scan_id(self) -> str:
        return "APEX-CMD-INJ"

    @property
    def name(self) -> str:
        return "OS Command Injection"

    @property
    def category(self) -> str:
        return "API8:2023 Injection"

    def run(self, endpoint: str, method: str, params: Dict) -> List[Dict]:
        self.results = []
        target = self.context.target_url.rstrip('/') + endpoint
        headers = self.context.get_headers()
        
        param_list = params.get('params', [])
        # Also could inject into body if schema exists (skipping for brevity in this initial pass, 
        # but logic is same as SQLi - recursive injection)
        
        for param in param_list:
             if param.get('in') in ['query', 'path']:
                 self._scan_param(method, target, headers, param.get('name'), param.get('in'))

        return self.results

    def _scan_param(self, method, target, headers, param_name, param_type):
        """Injects all command payloads into a parameter."""
        
        # Combine all payload lists
        all_payloads = []
        all_payloads.extend([(p, 'Unix') for p in PayloadLibrary.UNIX_CMD_PAYLOADS])
        all_payloads.extend([(p, 'Windows') for p in PayloadLibrary.WINDOWS_CMD_PAYLOADS])
        all_payloads.extend([(p, 'PowerShell') for p in PayloadLibrary.POWERSHELL_CMD_PAYLOADS])
        
        for payload, os_type in all_payloads:
            is_time_based = 'sleep' in payload or 'timeout' in payload
            
            try:
                test_url = target
                test_params = {}
                
                if param_type == 'query':
                    test_params = {param_name: payload}
                elif param_type == 'path':
                    test_url = test_url.replace(f"{{{param_name}}}", payload)
                
                start_time = time.time()
                timeout_val = 15 if is_time_based else 5
                
                res, record = HttpUtils.send_request_recorded(method, test_url, headers=headers, params=test_params, timeout=timeout_val)
                elapsed = time.time() - start_time
                
                if is_time_based:
                    if elapsed >= 5: 
                         self.add_finding(
                             title=f"Blind Command Injection ({os_type} - Time Based)",
                             description=f"The application responded in {elapsed:.2f}s, consistent with the injected time delay.",
                             severity="Critical",
                             evidence=f"Param: {param_name}\nPayload: {payload}\nResponse Time: {elapsed:.2f}s",
                             request_dump=record.format_request_dump(),
                             response_dump=record.format_response_dump()
                         )
                         return
                else:
                    matched_pattern = DetectionUtils.check_content_patterns(res.text, DetectionUtils.CMD_INJECTION_PATTERNS)
                    if matched_pattern:
                        self.add_finding(
                             title=f"OS Command Injection ({os_type})",
                             description=f"The application returned output execution results detected by pattern: {matched_pattern}",
                             severity="Critical",
                             evidence=f"Param: {param_name}\nPayload: {payload}\nMatched Pattern: {matched_pattern}\nSnippet: {res.text[:100]}",
                             request_dump=record.format_request_dump(),
                             response_dump=record.format_response_dump()
                         )
                        return

            except Exception as e:
                logger.debug(f"Cmd Inj failed for {param_name} with {payload}: {e}")
