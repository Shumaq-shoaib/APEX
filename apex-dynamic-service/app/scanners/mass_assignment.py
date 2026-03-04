import logging
import copy
from typing import List, Dict
from app.scanners.base import BaseScanner
from app.scanner_utils.http import HttpUtils

logger = logging.getLogger(__name__)

class MassAssignmentScanner(BaseScanner):
    """
    Scanner for Mass Assignment (Auto-Binding) vulnerabilities.
    Injects sensitive properties into JSON requests and analyzes responses for reflection or state changes.
    """

    @property
    def scan_id(self) -> str:
        return "APEX-MASS-ASSIGN"

    @property
    def name(self) -> str:
        return "Mass Assignment Scanner"
    
    @property
    def category(self) -> str:
        return "API3:2023 Broken Object Property Level Authorization"

    # Common sensitive parameters to inject
    SENSITIVE_PARAMS = {
        "isAdmin": True,
        "is_admin": True,
        "admin": True,
        "role": "admin",
        "roles": ["admin"],
        "type": "admin",
        "balance": 1000000,
        "credit": 1000000,
        "available_credit": 1000000,
        "mechanic_code": "TRAC_MECH1",
        "mechanic_api": "http://localhost:8888",
        "status": "verified",
        "isVerified": True,
        "confirmed": True
    }

    def run(self, endpoint: str, method: str, params: Dict) -> List[Dict]:
        """
        Scans a specific endpoint for Mass Assignment.
        Target only POST/PUT/PATCH methods with JSON bodies.
        """
        # Clear previous results to avoid duplication
        self.results = []
        
        if method not in ['POST', 'PUT', 'PATCH']:
            return []
        
        target = self.context.target_url.rstrip('/') + endpoint
        headers = self.context.get_headers()
        
        # We need to construct the body. In _scan_endpoint we pass {"params": ..., "schema": ...}
        # Ideally we might extract example body from schema or use parameters.
        # For simplicity, let's create a minimal valid body if we can, or just empty dict.
        # If 'params' has body info, use it.
        
        initial_data = {}
        # TODO: parse params['schema'] to generate valid initial data
        
        return self.scan(method, target, headers, initial_data)

    def scan(self, method, url, headers, initial_data=None):
        """
        Internal scan logic.
        """
        # We need a baseline to compare against
        try:
            # 1. Baseline Request
            # Ensure headers has Content-Type
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/json"

            baseline_res = HttpUtils.send_request(method, url, headers=headers, json=initial_data, timeout=5)
            # If baseline fails, we might not get good results, but we proceed cautiously
        except Exception as e:
            logger.debug(f"Mass Assignment: Baseline request failed for {url}: {e}")
            return []

        # Only scan if we have some JSON structure to work with, or if we want to blindly append
        base_json = initial_data if isinstance(initial_data, dict) else {}

        for param, value in self.SENSITIVE_PARAMS.items():
            payload = copy.deepcopy(base_json)
            payload[param] = value
            
            try:
                res, record = HttpUtils.send_request_recorded(method, url, headers=headers, json=payload, timeout=5)
                self._analyze_response(url, param, value, baseline_res, res, record)

            except Exception as e:
                logger.debug(f"Mass Assignment: Attack failed for {url} param {param}: {e}")

        return self.results

    def _analyze_response(self, url, param, value, baseline, attack_res, record=None):
        """
        Analyzes the attack response against the baseline.
        """
        req_dump = record.format_request_dump() if record else ""
        res_dump = record.format_response_dump() if record else ""

        try:
            res_json = attack_res.json()
            if isinstance(res_json, dict):
                if self._check_recursion(res_json, param, value):
                    self.add_finding(
                        title="Mass Assignment (Reflection)",
                        description=f"The injected parameter '{param}' was reflected in the response. This indicates the application might have bound the input to the internal object model.",
                        severity="High",
                        evidence=f"Param: {param}\nValue: {value}\nResponse Snippet: {str(res_json)[:200]}",
                        request_dump=req_dump,
                        response_dump=res_dump
                    )
                    return 
        except ValueError:
            pass

        if baseline.status_code != attack_res.status_code:
             if attack_res.status_code < 400 or (baseline.status_code >= 400 and attack_res.status_code < 400):
                self.add_finding(
                    title="Mass Assignment (Status Anomaly)",
                    description=f"Injecting '{param}' caused a status code change from {baseline.status_code} to {attack_res.status_code}. Investigate for logic bypass.",
                    severity="Medium",
                    evidence=f"Param: {param}\nBaseline Status: {baseline.status_code}\nAttack Status: {attack_res.status_code}",
                    request_dump=req_dump,
                    response_dump=res_dump
                )
        return

    def _check_recursion(self, obj, target_key, target_val):
        """Recursively checks if a key-value pair exists in a JSON object."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == target_key and str(v) == str(target_val):
                    return True
                if isinstance(v, (dict, list)):
                    if self._check_recursion(v, target_key, target_val):
                        return True
        elif isinstance(obj, list):
            for item in obj:
                if self._check_recursion(item, target_key, target_val):
                    return True
        return False
