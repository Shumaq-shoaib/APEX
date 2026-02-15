import httpx
from types import SimpleNamespace
from app.services.checks.base import BaseCheck
from app.models.dynamic import DynamicTestSession, DynamicTestCase, CheckType, Severity, CaseStatus

class BrokenAuthCheck(BaseCheck):
    async def execute(self, session: DynamicTestSession, case: DynamicTestCase):
        """
        Check for Brokern Authentication:
        1. Request with NO Authorization header.
        2. Request with INVALID Authorization header.
        
        If 200 OK -> Vulnerable.
        """
        target_url = f"{session.target_base_url.rstrip('/')}/{case.endpoint_path.lstrip('/')}"
        vulnerable = False
        evidence_req = ""
        evidence_resp = ""
        
        # Base headers (if we had any), but Auth Check specifically manipulates them.
        # We don't default the token here because Test 1 demands NO HEADER.
        
        async with httpx.AsyncClient(verify=False) as client:
            # Test 1: No Header
            try:
                # Log Attempt
                log_entry_1 = f"Probing No-Auth -> {case.method} {target_url}\n"
                case.logs = (case.logs or "") + log_entry_1
                self.db.commit()

                resp = await client.request(case.method, target_url)
                
                # Log Result
                case.logs = (case.logs or "") + f"Response: {resp.status_code} {resp.reason_phrase}\n"
                self.db.commit()

                if resp.status_code == 200:
                    vulnerable = True
                    evidence_req = f"{case.method} {target_url}\n(No Auth Header)"
                    evidence_resp = f"Status: {resp.status_code}\nBody: {resp.text[:500]}"
                    
                    self.report_finding(
                        case=case,
                        title="Broken Authentication (No Header)",
                        description="Endpoint returned 200 OK when no Authorization header was provided.",
                        severity=Severity.HIGH,
                        evidence_req=evidence_req,
                        evidence_resp=evidence_resp
                    )
            except Exception as e:
                # Log Error
                err_log = f"Request Failed: {str(e)}\n"
                case.logs = (case.logs or "") + err_log
                self.db.commit()

            # Test 2: Invalid Header (Only if not already vulnerable?)
            if not vulnerable:
                try:
                    # Log Attempt
                    log_entry_2 = f"Probing Invalid-Auth -> {case.method} {target_url} (Token: ...123)\n"
                    case.logs = (case.logs or "") + log_entry_2
                    self.db.commit()

                    resp = await client.request(case.method, target_url, headers={"Authorization": "Bearer invalid_token_123"})
                    
                    # Log Result
                    case.logs = (case.logs or "") + f"Response: {resp.status_code} {resp.reason_phrase}\n"
                    self.db.commit()

                    if resp.status_code == 200:
                        vulnerable = True
                        evidence_req = f"{case.method} {target_url}\nAuthorization: Bearer invalid_token_123"
                        evidence_resp = f"Status: {resp.status_code}\nBody: {resp.text[:500]}"
                        
                        self.report_finding(
                            case=case,
                            title="Broken Authentication (Invalid Token)",
                            description="Endpoint returned 200 OK with an invalid Bearer token.",
                            severity=Severity.HIGH,
                            evidence_req=evidence_req,
                            evidence_resp=evidence_resp
                        )
                except Exception as e:
                    err_log = f"Request Failed: {str(e)}\n"
                    case.logs = (case.logs or "") + err_log
                    self.db.commit()

        # Update Case Status
        case.status = CaseStatus.EXECUTED
        # Note: 'case' result doesn't explicitly track 'VULNERABLE' status on the case itself, 
        # but the Finding is linked. Logic flow in Engine usually handles database commit.
