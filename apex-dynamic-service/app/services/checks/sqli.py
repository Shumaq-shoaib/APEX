import httpx
import logging
from app.services.checks.base import BaseCheck
from app.models.dynamic import DynamicTestSession, DynamicTestCase, Severity

logger = logging.getLogger(__name__)

class SQLInjectionCheck(BaseCheck):
    async def execute(self, session: DynamicTestSession, case: DynamicTestCase):
        """
        Check for SQL Injection (Error-Based & Simple Boolean)
        """
        target_path = case.endpoint_path
        payloads = ["'", "\"", "' OR 1=1 --", "\" OR 1=1 --"]
        
        if "?" not in target_path:
             target_path += "?"
        
        vulnerable = False
        evidence = []

        headers = {}
        if session.auth_token:
            headers["Authorization"] = f"Bearer {session.auth_token}"

        async with httpx.AsyncClient(verify=False, headers=headers) as client:
            for payload in payloads:
                # Naive Injection: append test_param
                test_url = f"{session.target_base_url.rstrip('/')}{target_path}&test_param={payload}"
                
                try:
                    resp = await client.request(case.method, test_url)
                    
                    # Error Detection (MySQL/Postgres common errors)
                    errors = ["syntax error", "mysql_fetch", "native client", "check the manual"]
                    if any(e in resp.text.lower() for e in errors):
                        vulnerable = True
                        evidence.append(f"Payload: {payload} -> Error detected")
                        
                        # Log it
                        case.logs = (case.logs or "") + f"[SQLi] Payload {payload} Triggered Error\n"
                        self.db.commit()

                except Exception as e:
                    logger.error(f"SQLi Check Error: {e}")
                    pass
        
        if vulnerable:
            self.report_finding(
                case=case,
                title="Potential SQL Injection",
                description="Database error messages detected in response.",
                severity=Severity.CRITICAL,
                evidence_req=str(payloads),
                evidence_resp="\n".join(evidence)
            )
        else:
            case.logs = (case.logs or "") + "[SQLi] No error messages detected.\n"
