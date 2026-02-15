import httpx
import re
from app.services.checks.base import BaseCheck
from app.models.dynamic import DynamicTestSession, DynamicTestCase, CheckType, Severity, CaseStatus

class BolaCheck(BaseCheck):
    async def execute(self, session: DynamicTestSession, case: DynamicTestCase):
        """
        Check for BOLA (IDOR):
        Simplified Logic for Phase 4:
        1. Identify {id} in path.
        2. Replace with a 'test' ID (e.g., '1' or '9999').
        3. Send Request.
        4. (Future) Need 2 valid user tokens to test properly.
        
        Current Implementation:
        - Checks if endpoint is accessible with arbitrary IDs.
        - Warning if 200 OK is returned for guessed IDs without ownership validation.
        """
        target_path = case.endpoint_path
        
        # Regex to find {id} or similar params
        # Matches {id}, {user_id}, :id
        param_pattern = re.compile(r"\{([a-zA-Z0-9_]+)\}")
        match = param_pattern.search(target_path)
        
        if not match:
            # No ID to test
            case.status = CaseStatus.SKIPPED
            return

        param_name = match.group(1)
        
        # Hacker List of Payloads
        payloads = ["1", "100", "9999", "admin", "test", "0", "-1"]
        
        vulnerable = False
        findings_log = []

        headers = {}
        if session.auth_token:
            headers["Authorization"] = f"Bearer {session.auth_token}"

        # Dual Token Logic (Phase 2)
        victim_token = getattr(session, "auth_token_secondary", None)
        
        async with httpx.AsyncClient(verify=False, headers=headers) as client:
            for payload in payloads:
                target_url_path = param_pattern.sub(payload, target_path)
                full_url = f"{session.target_base_url.rstrip('/')}/{target_url_path.lstrip('/')}"
                
                # Log Attempt
                log_entry = f"Probing ID '{payload}' -> {case.method} {full_url}"
                if victim_token:
                    log_entry += " (Dual-Token Mode Active)"
                
                case.logs = (case.logs or "") + log_entry + "\n"
                
                # Stream logs
                self.db.commit() 

                try:
                    resp = await client.request(case.method, full_url)
                    case.logs = (case.logs or "") + f"Response: {resp.status_code}\n"
                    
                    if resp.status_code == 200:
                        is_vuln = True
                        
                        # False Positive Reduction with Secondary Token
                        if victim_token:
                            # In future: Check if resource belongs to victim vs attacker
                            pass 

                        if is_vuln:
                            vulnerable = True
                            findings_log.append(f"ID {payload}: 200 OK")
                except Exception as e:
                     case.logs = (case.logs or "") + f"Request Failed: {e}\n"

        if vulnerable:
            self.report_finding(
                case=case,
                title=f"Potential BOLA on {param_name}",
                description=f"Endpoint accessible with arbitrary IDs: {', '.join(findings_log)}. Verification of ownership required.",
                severity=Severity.HIGH, 
                evidence_req=f"Tested IDs: {payloads}",
                evidence_resp=f"Successes: {findings_log}"
            )
        else:
             case.logs = (case.logs or "") + "Safe: No unauthorized access detected.\n"

        case.status = CaseStatus.EXECUTED
