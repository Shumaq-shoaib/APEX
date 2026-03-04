from typing import List, Dict, Any
from urllib.parse import urlparse

from app.scanners.base import BaseScanner
from app.scanner_utils.http import HttpUtils
from app.scanner_utils.payloads import PayloadLibrary

class CorsScanner(BaseScanner):
    @property
    def scan_id(self) -> str:
        return "APEX-CORS"

    @property
    def name(self) -> str:
        return "CORS Misconfiguration Scanner"

    @property
    def category(self) -> str:
        return "API7:2023 Security Misconfiguration"

    @property
    def description(self) -> str:
        return "Detects overly permissive Cross-Origin Resource Sharing (CORS) configurations."

    def run(self, endpoint: str, method: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.results = []
        target_url = f"{self.context.target_url.rstrip('/')}{endpoint}"
        
        # Determine target domain to generate dynamic evil origins
        parsed_url = urlparse(target_url)
        domain_name = parsed_url.hostname or "localhost"
        protocol = parsed_url.scheme or "http"
        
        dynamic_evil_origins = [
            f"{protocol}://attackersite.com",
            f"{protocol}://{domain_name}.attackersite.com",
            f"{protocol}://{domain_name}.attacker.com"
        ]
        
        origins_to_test = dynamic_evil_origins + PayloadLibrary.CORS_EVIL_ORIGINS

        for origin in origins_to_test:
            # Send an OPTIONS or the actual method request with the Origin header
            headers = {"Origin": origin}
            test_method = "OPTIONS" if method.upper() in ["POST", "PUT", "DELETE", "PATCH"] else method.upper()
            
            record = HttpUtils.send_request_recorded(
                method=test_method,
                url=target_url,
                headers=headers,
                auth=self.context.auth
            )

            if not record or not record.response_headers:
                continue

            # Convert headers to lowercase keys for easy lookup
            res_headers = {k.lower(): v for k, v in record.response_headers.items()}
            
            acao = res_headers.get("access-control-allow-origin")
            acac = res_headers.get("access-control-allow-credentials", "").lower() == "true"
            
            if acao:
                severity = "Info"
                vuln_found = False
                desc_detail = ""

                # Check for reflection or wildcard
                if acao == origin:
                    vuln_found = True
                    if acac:
                        severity = "High"
                        desc_detail = f"Arbitrary origin '{origin}' is reflected, and credentials are allowed. This allows an attacker site to read authenticated cross-origin responses."
                    else:
                        severity = "Medium"
                        desc_detail = f"Arbitrary origin '{origin}' is reflected, but credentials are not allowed."
                elif acao == "*" and acac:
                    # Browsers technically don't allow ACAO: * with ACAC: true, but finding it is a misconfiguration
                    vuln_found = True
                    severity = "Medium" 
                    desc_detail = "Wildcard origin '*' is allowed with credentials (browsers may block this, but it shows poor configuration)."
                elif acao == "*":
                    vuln_found = True
                    severity = "Low"
                    desc_detail = "Wildcard origin '*' is allowed. This may expose public data via CORS."
                elif acao == "null":
                    vuln_found = True
                    severity = "High" if acac else "Medium"
                    desc_detail = "Origin 'null' is allowed. This bypasses many sandbox restrictions."

                if vuln_found:
                    self.add_finding(
                        record=record,
                        title=f"CORS Misconfiguration ({severity})",
                        description=desc_detail,
                        severity=severity,
                        evidence=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}"
                    )
                    break # Stop after finding the most severe issue for this endpoint
                    
        return self.results
