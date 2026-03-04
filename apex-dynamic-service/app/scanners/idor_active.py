from typing import List, Dict
import re
import sys
import os

import urllib.parse
import copy
import logging
from app.scanners.base import BaseScanner
from app.scanner_utils.payloads import PayloadLibrary
from app.scanner_utils.detection import DetectionUtils
from app.scanner_utils.http import HttpUtils

class ActiveIdorScanner(BaseScanner):
    """
    Simulates ZAP's Access Control / IDOR Checks (Active).
    Iterates through endpoints with path parameters and fuzzes the IDs.
    """

    @property
    def scan_id(self) -> str:
        return "APEX-IDOR-ACTIVE"

    @property
    def name(self) -> str:
        return "Active IDOR Scanner"

    @property
    def category(self) -> str:
        return "API1:2023 Broken Object Level Authorization"

    def run(self, endpoint: str, method: str, params: Dict) -> List[Dict]:
        self.results = []
        target = self.context.target_url.rstrip('/') + endpoint
        headers = self.context.get_headers()
        
        extracted_params = params.get('params', [])
        path_params = [p for p in extracted_params if p.get('in') == 'path']
        
        if not path_params:
            return self.results

        # 0. Automated Token Swapping (BOLA/IDOR Proof)
        if self.context.auth.secondary_token:
            secondary_headers = self.context.get_secondary_headers()
            
            for param in path_params:
                param_name = param['name']
                
                # We need a valid ID to test cross-access. Ideally, this would be scraped from previous responses.
                # For now, we will test the baseline request with User A, and if successful, replay it as User B.
                try:
                    # Baseline with Primary Token
                    example_id = "35" # Safe fallback
                    if "id" in param_name.lower() or "number" in param_name.lower():
                        test_url = target.replace(f"{{{param_name}}}", example_id)
                        
                        primary_res, primary_rec = HttpUtils.send_request_recorded(method, test_url, headers=headers, timeout=5)
                        
                        if primary_res.status_code >= 200 and primary_res.status_code < 300 and len(primary_res.text) > 5:
                            
                            # Replay with Secondary Token
                            sec_res, sec_rec = HttpUtils.send_request_recorded(method, test_url, headers=secondary_headers, timeout=5)
                            
                            if sec_res.status_code >= 200 and sec_res.status_code < 300:
                                # Compare bodies to prove cross-access
                                if primary_res.text == sec_res.text:
                                    self.add_finding(
                                        title=f"BOLA / IDOR (Token Swap Proof)",
                                        description=f"Automated Token Swapping proved BOLA. User B successfully accessed User A's resource at ID '{example_id}'. The response bodies were identical.",
                                        severity="Critical",
                                        evidence=f"Method: {method}\nURL: {test_url}\nPrimary Status: {primary_res.status_code}\nSecondary Status: {sec_res.status_code}",
                                        request_dump=sec_rec.format_request_dump(),
                                        response_dump=sec_rec.format_response_dump()
                                    )
                                    # We found a definitive BOLA on this parameter, we can skip further noisy fuzzing for it
                                    continue
                except Exception as e:
                    logging.debug(f"Token swapping failed for {target}: {e}")

        for param in path_params:
            param_name = param['name']
            
            # Heuristic: Only fuzz parameters that look like object IDs
            if "id" not in param_name.lower() and "number" not in param_name.lower():
                continue

            # 1. Standard ID Fuzzing & Encoding
            for raw_id in PayloadLibrary.IDOR_TEST_IDS + PayloadLibrary.IDOR_SELF_ALIASES:
                # Payloads: [Raw, URL Encoded, Double URL Encoded]
                payloads = [str(raw_id)]
                if isinstance(raw_id, int):
                     # Add Negative
                     payloads.append(str(-1 * raw_id))
                
                # Encoding Variants for String/Int
                encoded = urllib.parse.quote(str(raw_id))
                double_encoded = urllib.parse.quote(encoded)
                if encoded != str(raw_id): payloads.append(encoded)
                if double_encoded != encoded: payloads.append(double_encoded)
                
                # Path Traversal Variants
                payloads.append(f"../{raw_id}")
                payloads.append(f"..%2f{raw_id}")
                
                for payload in set(payloads):
                     fuzzed_url = target.replace(f"{{{param_name}}}", payload)
                     if fuzzed_url == target: continue
                     
                     # Test A: ID Replacement
                     self._test_idor(method, fuzzed_url, headers, param_name, payload, "ID Fuzzing")

            # 2. HTTP Parameter Pollution (HPP)
            for test_id in [0, 1]:
                 safe_url = target.replace(f"{{{param_name}}}", "35") 
                 if safe_url != target:
                     self._test_idor(method, safe_url + f"?{param_name}={test_id}", headers, param_name, test_id, "HPP")

            # 3. Method Swapping
            for test_id in [1]:
                 fuzzed_url = target.replace(f"{{{param_name}}}", str(test_id))
                 for swap_method in ["DELETE", "PUT", "PATCH", "GET"]:
                     if swap_method == method: continue
                     self._test_idor(swap_method, fuzzed_url, headers, param_name, test_id, f"Method Swap ({swap_method})")
        
        return self.results

    def _test_idor(self, method, url, headers, param_name, test_id, context_label):
        try:
            res, record = HttpUtils.send_request_recorded(method, url, headers=headers, timeout=5)
            
            if res.status_code >= 200 and res.status_code < 300:
                if len(res.text) < 5: return

                discovered_key = DetectionUtils.check_content_patterns(res.text, DetectionUtils.IDOR_SENSITIVE_KEYS)
                enrichment = f"\nDiscovered sensitive key: {discovered_key}" if discovered_key else ""

                self.add_finding(
                    title=f"Potential IDOR ({context_label})",
                    description=f"The endpoint returned a 2xx success code when accessing ID '{test_id}' via {context_label}. Verify authorization.{enrichment}",
                    severity="High",
                    evidence=f"Method: {method}\nURL: {url}\nPayload: {test_id}\nStatus: {res.status_code}",
                    request_dump=record.format_request_dump(),
                    response_dump=record.format_response_dump()
                )

        except Exception as e:
            logging.debug(f"IDOR check failed for {url}: {e}")
