import httpx
from app.services.checks.base import BaseCheck
from app.models.dynamic import DynamicTestSession, DynamicTestCase, Severity

class XSSCheck(BaseCheck):
    async def execute(self, session: DynamicTestSession, case: DynamicTestCase):
        """
        Check for Reflected XSS
        """
        canary = "<script>alert('apex')</script>"
        target_path = case.endpoint_path
        
        if "?" not in target_path:
             target_path += "?"

        headers = {}
        if session.auth_token:
            headers["Authorization"] = f"Bearer {session.auth_token}"

        async with httpx.AsyncClient(verify=False, headers=headers) as client:
            # Inject into query param
            test_url = f"{session.target_base_url.rstrip('/')}{target_path}&q={canary}"
            
            try:
                resp = await client.request(case.method, test_url)
                
                # Check for reflection
                if canary in resp.text:
                    self.report_finding(
                        case=case,
                        title="Reflected XSS",
                        description=f"Payload {canary} was reflected in the response without encoding.",
                        severity=Severity.HIGH,
                        evidence_req=test_url,
                        evidence_resp=resp.text[:500]
                    )
            except Exception:
                pass
