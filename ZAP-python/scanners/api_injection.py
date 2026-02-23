from typing import List, Dict
import re
import sys
import os
# Fix import path if run directly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import copy
from scanners.base import BaseScanner
from utils.payloads import PayloadLibrary
from utils.detection import DetectionUtils
from utils.http_utils import HttpUtils

class SqlInjectionScanner(BaseScanner):
    """
    Simulates ZAP's SqlInjectionScanRule.
    Focuses on Error-Based and Boolean-Based injection.
    """

    @property
    def scan_id(self) -> str:
        return "API-SQLI"

    @property
    def name(self) -> str:
        return "SQL Injection"

    @property
    def category(self) -> str:
        return "API8:2023 Injection"

    def run(self, endpoint: str, method: str, params_dict: Dict) -> List[Dict]:
        self.results = []
        target = self.context.target_url.rstrip('/') + endpoint
        headers = self.context.get_headers()
        
        extracted_params = params_dict.get("params", []) 
        body_schema = params_dict.get("schema")
        
        # 1. Parameter Injection (Query/Path)
        for param in extracted_params:
            if param.get('in') not in ['query', 'path']:
                continue
            
            param_name = param['name']
            
            # Polyglots (Advanced)
            for payload in PayloadLibrary.POLYGLOT_PAYLOADS:
                 self._test_injection(method, target, headers, param_name, payload, param.get('in'), type_label="Advanced Injection (Polyglot)")

            # SQLi Error-Based
            for payload in PayloadLibrary.SQL_ERROR_PAYLOADS:
                injected_value = f"1{payload}"
                self._test_injection(method, target, headers, param_name, injected_value, param_type=param.get('in'), type_label="SQL Injection")

            # SQLi Time-Based
            self._run_time_based_sqli(method, target, headers, param_name, param.get('in'))

            # NoSQL Injection (Query/Path - usually string based)
            for payload in [p for p in PayloadLibrary.NOSQL_PAYLOADS if isinstance(p, str)]:
                 self._test_injection(method, target, headers, param_name, payload, param_type=param.get('in'), type_label="NoSQL Injection")

        # 2. Body Injection (JSON) - Recursive
        if body_schema:
            base_body = self._generate_sample_body(body_schema)
            if base_body:
                self._fuzz_json_body(method, target, headers, base_body)

        return self.results

    def _run_time_based_sqli(self, method, target, headers, param_name, param_type):
        """Run time-based SQLi checks."""
        time_payloads = {
            "Postgres": "'; SELECT pg_sleep(5); --",
            "MySQL": "'; SLEEP(5); --",
            "SQLServer": "'; WAITFOR DELAY '0:0:5'; --",
            "SQLite": "';  SELECT randomblob(100000000); --" # Heavy function approximation
        }
        for db, payload in time_payloads.items():
            self._test_time_injection(method, target, headers, param_name, payload, param_type, 5, db)

    def _fuzz_json_body(self, method, target, headers, base_body):
        """Recursively inject payloads into a JSON body."""
        def traverse_and_inject(obj, path=[]):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    traverse_and_inject(v, path + [k])
                    
                    if isinstance(v, (str, int, type(None))):
                        # Advanced NoSQL
                        for payload in PayloadLibrary.NOSQL_PAYLOADS:
                            new_body = copy.deepcopy(base_body)
                            self._set_value_by_path(new_body, path + [k], payload)
                            self._test_injection(method, target, headers, "body", new_body, param_type="body", type_label="NoSQL Injection")
                        
                        # Polyglots in JSON
                        for payload in PayloadLibrary.POLYGLOT_PAYLOADS:
                             new_body = copy.deepcopy(base_body)
                             self._set_value_by_path(new_body, path + [k], payload)
                             self._test_injection(method, target, headers, "body", new_body, param_type="body", type_label="Advanced Injection")

            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                     traverse_and_inject(v, path + [i])

        traverse_and_inject(base_body)
    
    # Helper methods _set_value_by_path, _generate_sample_body, _test_time_injection, _test_injection remain the same... 
    # (Checking if I need to include them to not delete them?)
    # I used StartLine and EndLine to target the `run`, `_run_time_based_sqli` and `_fuzz_json_body` methods.
    # I should be careful not to delete the helpers below.
    # The EndLine 221 goes to the end of the file.
    # So I MUST include the helpers in the ReplacementContent or adjust EndLine.
    # `_test_injection` starts at 168.
    # `_fuzz_json_body` ends at 112.
    # I will split this into multiple replace calls or include everything.
    # To be safe, I'll include the helpers that are *below* `_fuzz_json_body` if I'm replacing everything down to 221.
    # Actually, `_test_injection` is quite long.
    # I will just replace the `run` method and `_run_time_based_sqli` and `_fuzz_json_body`.
    # `run` is lines 36-72.
    # `_run_time_based_sqli` is 74-83.
    # `_fuzz_json_body` is 84-112.
    # So I can replace 36-112.
    # And leave the rest.

    def _set_value_by_path(self, obj, path, value):
        for key in path[:-1]:
            obj = obj[key]
        obj[path[-1]] = value

    def _generate_sample_body(self, schema):
        if not schema: return {}
        if schema.get('type') == 'object':
            properties = schema.get('properties', {})
            obj = {}
            for name, prop in properties.items():
                obj[name] = self._generate_sample_body(prop)
            return obj
        elif schema.get('type') == 'string':
            return "test"
        elif schema.get('type') == 'integer':
            return 1
        elif schema.get('type') == 'boolean':
            return False
        return "test"

    def _test_time_injection(self, method, target, headers, param_name, payload, param_type, delay, db_type):
        try:
            test_url = target
            test_json = None
            test_params = {}
            if param_type == 'query':
                test_params = {param_name: payload}
            elif param_type == 'path':
                test_url = test_url.replace(f"{{{param_name}}}", str(payload))
            elif param_type == 'body':
                test_json = payload
            
            res, record = HttpUtils.send_request_recorded(method, test_url, headers=headers, params=test_params, json=test_json, timeout=delay + 5)
            elapsed = res.elapsed.total_seconds()
            if elapsed >= delay:
                self.add_finding(
                    title=f"Blind SQL Injection ({db_type} - Time Based)",
                    description=f"The endpoint took {elapsed:.2f}s to respond, which is consistent with the injected sleep command ({delay}s).",
                    severity="Critical",
                    evidence=f"Param: {param_name}\nPayload: {payload}\nResponse Time: {elapsed:.2f}s",
                    request_dump=record.format_request_dump(),
                    response_dump=record.format_response_dump()
                )
        except Exception as e:
             import logging
             logging.debug(f"Time-based SQLi check failed for {param_name}: {e}")

    def _test_injection(self, method, target, headers, param_name, injected_value, param_type, type_label="SQL Injection"):
        try:
            test_url = target
            test_params = {}
            test_json = None
            
            if param_type == 'query':
                test_params = {param_name: injected_value}
            elif param_type == 'path':
                test_url = test_url.replace(f"{{{param_name}}}", str(injected_value))
            elif param_type == 'body':
                test_json = injected_value
            
            res, record = HttpUtils.send_request_recorded(method, test_url, headers=headers, params=test_params, json=test_json, timeout=5)
            
            if "NoSQL" in type_label:
                 matched_errors = DetectionUtils.check_error_patterns(res.text, {"MongoDB": DetectionUtils.DBMS_ERRORS["MongoDB"]})
            else:
                 matched_errors = DetectionUtils.check_error_patterns(res.text, DetectionUtils.DBMS_ERRORS)

            for db, is_found in matched_errors.items():
                if is_found:
                    self.add_finding(
                        title=f"{type_label} ({db})",
                        description=f"Possible {type_label} in parameter '{param_name}' detected via error message.",
                        severity="High",
                        evidence=f"Param: {param_name}\nPayload: {injected_value}\nMatched Error in Response",
                        request_dump=record.format_request_dump(),
                        response_dump=record.format_response_dump()
                    )
                    return 

            if "NoSQL" in type_label and isinstance(injected_value, dict):
                if res.status_code == 200:
                    self.add_finding(
                        title=f"{type_label} (Logic Bypass)",
                        description=f"The endpoint returned HTTP 200 OK for a NoSQL logic bypass payload. This suggests it accepted the query.",
                        severity="Critical",
                        evidence=f"Param: {param_name}\nPayload: {injected_value}\nResponse Code: {res.status_code}",
                        request_dump=record.format_request_dump(),
                        response_dump=record.format_response_dump()
                    )

        except Exception as e:
            import logging
            logging.debug(f"Injection check failed for {param_name}: {e}")
        
        return self.results
