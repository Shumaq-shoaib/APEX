from abc import ABC, abstractmethod
from sqlalchemy.orm import Session
from app.models.dynamic import DynamicTestSession, DynamicTestCase, DynamicFinding, DynamicEvidence, Severity

from app.services.reporting import ReportManager

class BaseCheck(ABC):
    def __init__(self, db: Session):
        self.db = db

    @abstractmethod
    async def execute(self, session: DynamicTestSession, case: DynamicTestCase):
        """
        Execute the vulnerability check logic.
        :param session: The current test session.
        :param case: The specific test case to run (contains endpoint, method, etc.).
        """
        pass

    def report_finding(self, case: DynamicTestCase, title: str, description: str, severity: Severity, evidence_req: str = None, evidence_resp: str = None):
        """
        Helper to save a finding to the database.
        """
        # Enrich with Reporting Data
        cvss = ReportManager.get_cvss_score(case.check_type, severity)
        remediation = ReportManager.get_remediation(case.check_type)

        finding = DynamicFinding(
            session_id=case.session_id,
            test_case_id=case.id,
            endpoint_path=case.endpoint_path,
            method=case.method,
            check_type=case.check_type,
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss,
            remediation=remediation
        )
        self.db.add(finding)
        self.db.commit()
        self.db.refresh(finding)

        if evidence_req or evidence_resp:
            evidence = DynamicEvidence(
                finding_id=finding.id,
                request_dump=evidence_req,
                response_dump=evidence_resp
            )
            self.db.add(evidence)
            self.db.commit()
        
        return finding
