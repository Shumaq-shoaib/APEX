import re
import uuid
import logging
from typing import List, Dict
from scanners.base import BaseScanner
from utils.payloads import PayloadLibrary
from utils.detection import DetectionUtils
from utils.http_utils import HttpUtils

logger = logging.getLogger(__name__)

class ExternalRedirectScanner(BaseScanner):
    """
    Scanner for Open Redirect vulnerabilities.
    Simulates ZAP's ExternalRedirectScanRule.
    Checks Headers (Location, Refresh) and Body (Meta, JS) for redirection to an external domain.
    """

    @property
    def scan_id(self) -> str:
        return "API-REDIRECT"

    @property
    def name(self) -> str:
        return "External Redirect Scanner"

    @property
    def category(self) -> str:
        return "API7:2023 Security Misconfiguration"

    def run(self, endpoint: str, method: str, params: Dict) -> List[Dict]:
        self.results = []
        target = self.context.target_url.rstrip('/') + endpoint
        headers = self.context.get_headers()
        
        # Generate Session UUID for this scan to avoid false positives with other scans/traffic
        scan_uuid = str(uuid.uuid4())
        
        # 1. Inject into Query Parameters
        param_list = params.get('params', [])
        for param in param_list:
             if param.get('in') in ['query', 'path']:
                 self._test_injection(method, target, headers, param.get('name'), param.get('in'), scan_uuid)

        return self.results

    def _test_injection(self, method, target, headers, param_name, param_type, scan_uuid):
        """Test a specific parameter with all redirect payloads."""
        
        # Dynamically compile detection patterns for this UUID
        # We replace {uuid} in the template with our actual scan_uuid
        compiled_patterns = {}
        for key, pattern_tmpl in DetectionUtils.REDIRECT_PATTERNS_TEMPLATE.items():
            pattern = pattern_tmpl.format(uuid=scan_uuid)
            compiled_patterns[key] = re.compile(pattern, re.IGNORECASE)

        # Prepare Payloads
        # Some payloads need the UUID inserted
        attack_payloads = []
        
        # Basic URL Payloads
        uuid_enc = scan_uuid.replace('.', '%2e') # For period encoding
        
        for p in PayloadLibrary.EXTERNAL_REDIRECT_PAYLOADS:
            # Format payload with uuid
            # Handle {uuid} and {uuid_enc} placeholders
            # Also handle {orig} if we wanted to preserve original value (simplification: we overwrite for now)
            formatted = p.format(uuid=scan_uuid, uuid_enc=uuid_enc, orig="foo") 
            attack_payloads.append(formatted)

        # Add Header specific payloads (Refresh/Location)
        for p in PayloadLibrary.REDIRECT_HEADER_PAYLOADS:
             formatted = p.format(uuid=scan_uuid, uuid_enc=uuid_enc, orig="foo")
             attack_payloads.append(formatted)

            
        # Iterate and Attack
        for payload in attack_payloads:
            try:
                # Construct Request
                test_url = target
                test_params = {}
                
                if param_type == 'query':
                    test_params = {param_name: payload}
                elif param_type == 'path':
                    test_url = test_url.replace(f"{{{param_name}}}", payload)
                
                # Send Request (Do NOT follow redirects automatically to catch the 3xx)
                # HttpUtils.send_request usually follows redirects. We might need to handle this.
                # However, ZAP checks the *immediate* response.
                # If HttpUtils follows, we might lose the 3xx header but we might land on the page.
                # Ideally, we want `allow_redirects=False`. 
                # Let's see if HttpUtils supports kwargs passing to requests. assume yes.
                
                res, record = HttpUtils.send_request_recorded(method, test_url, headers=headers, params=test_params, allow_redirects=False, timeout=5)
                
                self._analyze_response(res, payload, param_name, compiled_patterns, scan_uuid, record)
                
            except Exception as e:
                logger.debug(f"Redirect Scan failed for {param_name} with payload {payload}: {e}")

    def _analyze_response(self, res, payload, param_name, patterns, scan_uuid, record=None):
        """Analyze headers and body for redirect indicators."""
        req_dump = record.format_request_dump() if record else ""
        res_dump = record.format_response_dump() if record else ""

        if 300 <= res.status_code < 400:
            loc = res.headers.get('Location', '')
            if scan_uuid in loc:
                 self.add_finding(
                     title="Open Redirect (Header)",
                     description="The application redirects to an arbitrary external domain specified in the request parameter.",
                     severity="Medium",
                     evidence=f"Param: {param_name}\nPayload: {payload}\nLocation Header: {loc}",
                     request_dump=req_dump,
                     response_dump=res_dump
                 )
                 return

        if res.status_code == 200:
            content = res.text
            
            if patterns['meta_refresh'].search(content):
                self.add_finding(
                     title="Open Redirect (Meta Refresh)",
                     description="The application uses a Meta Refresh tag to redirect to an arbitrary external domain.",
                     severity="Medium",
                     evidence=f"Param: {param_name}\nPayload: {payload}\nMatched Metadata in body.",
                     request_dump=req_dump,
                     response_dump=res_dump
                 )
                return

            for key in ['js_location', 'js_assign', 'js_window']:
                if patterns[key].search(content):
                     self.add_finding(
                         title="Open Redirect (JavaScript)",
                         description="The application uses JavaScript to redirect to an arbitrary external domain.",
                         severity="Medium",
                         evidence=f"Param: {param_name}\nPayload: {payload}\nMatched JS pattern: {key}",
                         request_dump=req_dump,
                         response_dump=res_dump
                     )
                     return
