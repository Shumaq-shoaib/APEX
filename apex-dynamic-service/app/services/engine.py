import logging
import asyncio
import io
import contextlib
import json
from datetime import datetime
from sqlalchemy.orm import Session
from app.models.dynamic import DynamicTestCase, CaseStatus, DynamicTestSession, SessionStatus, CheckType, Severity, DynamicFinding, DynamicEvidence
from app.services.reporting import ReportManager

# Import ZAP-python components (Path added in main.py)
try:
    from core.context import ScanContext, AuthConfig
    from scanners.base import BaseScanner
except ImportError as e:
    logging.error(f"Failed to import ZAP-python modules: {e}")

# Configure logging
logger = logging.getLogger(__name__)

class AttackEngine:
    def __init__(self, session_id: str, db_session: Session):
        self.session_id = session_id
        self.db = db_session
        self.scanners = []
        self._load_zap_scanners()
        if not self.scanners:
            logger.error(f"CRITICAL: No ZAP scanners loaded for session {session_id}!")

    def _load_zap_scanners(self):
        """Load all scanners from ZAP-python dynamically."""
        import importlib
        import pkgutil
        import scanners
        from inspect import isclass

        # Create a dummy context for initialization
        dummy_context = ScanContext(target_url="http://localhost")
        
        try:
            package = scanners
            prefix = package.__name__ + "."
            for _, name, _ in pkgutil.iter_modules(package.__path__, prefix):
                if name == "scanners.base":
                    continue
                try:
                    module = importlib.import_module(name)
                    for attribute_name in dir(module):
                        attribute = getattr(module, attribute_name)
                        if (isclass(attribute) and 
                            attribute.__module__ == name and
                            issubclass(attribute, BaseScanner) and 
                            attribute is not BaseScanner):
                            
                            scanner_instance = attribute(dummy_context)
                            self.scanners.append(scanner_instance)
                            logger.info(f"Loaded ZAP Scanner: {scanner_instance.name} [{scanner_instance.scan_id}]")
                except Exception as e:
                    logger.error(f"Failed to load ZAP scanner from {name}: {e}")
        except Exception as e:
            logger.error(f"Failed to iterate ZAP scanners: {e}")

    def _get_scanners_for_check(self, check_type: CheckType) -> list:
        """Map APEX CheckType to ZAP-python Scanners."""
        mapping = {
            CheckType.BOLA: ["API-ACTIVE-IDOR"],
            CheckType.BROKEN_AUTH: ["API-JWT-SCAN", "API-SEC-HEADERS"],
            CheckType.SQLI: ["API-SQLI"],
            CheckType.INJECTION: ["API-CMD-INJ"],
            CheckType.SSRF: ["API-SSRF"],
            CheckType.DATA_EXPOSURE: ["API-IDOR-PASSIVE", "API-MASS-ASSIGN"],
            CheckType.OTHER: ["API-REDIRECT", "API-XXE"]
        }
        target_ids = mapping.get(check_type, [])
        return [s for s in self.scanners if s.scan_id in target_ids]

    async def run_test_case(self, test_case: DynamicTestCase, target_base_url: str, auth_token: str | None = None):
        """
        Executes ZAP-python scanners against the target for the given test case.
        """
        full_url = f"{target_base_url.rstrip('/')}{test_case.endpoint_path}"
        method = test_case.method.upper()
        
        start_msg = f"[{datetime.utcnow().time()}] Starting ZAP-enhanced {test_case.check_type} on {method} {full_url} ...\n"
        test_case.logs = (test_case.logs or "") + start_msg
        self.db.commit()

        # Initialize ZAP Context
        zap_context = ScanContext(
            target_url=target_base_url,
            auth=AuthConfig(token=auth_token.split(" ")[1] if auth_token and " " in auth_token else auth_token)
        )

        # 1. Get Blueprint to find endpoint metadata
        session = self.db.query(DynamicTestSession).get(self.session_id)
        blueprint = json.loads(session.spec.blueprint_json) if session and session.spec and session.spec.blueprint_json else {}
        endpoints = blueprint.get("endpoints", [])
        
        # Find matching endpoint in blueprint
        endpoint_meta = next(
            (ep for ep in endpoints if ep.get("path") == test_case.endpoint_path and ep.get("method") == method), 
            {"params": [], "schema": {}, "example": {}}
        )

        relevant_scanners = self._get_scanners_for_check(test_case.check_type)
        
        if not relevant_scanners:
            msg = f"[{datetime.utcnow().time()}] No ZAP scanners mapped for {test_case.check_type}. Skipping.\n"
            test_case.logs = (test_case.logs or "") + msg
            test_case.status = CaseStatus.SKIPPED
            self.db.commit()
            return

        for scanner in relevant_scanners:
            # Update scanner context for this run
            scanner.context = zap_context
            scanner.results = []
            
            scanner_msg = f"--- Running Scanner: {scanner.name} [{scanner.scan_id}] ---\n"
            test_case.logs = (test_case.logs or "") + scanner_msg
            self.db.commit()

            try:
                # Run sync scanner in a thread to keep async loop alive
                # Passing full endpoint metadata for improved accuracy
                findings = await asyncio.to_thread(
                    scanner.run, 
                    test_case.endpoint_path, 
                    method, 
                    endpoint_meta
                )
                
                if findings:
                    for f in findings:
                        self._report_zap_finding(test_case, f)
                        test_case.logs += f"[VULNERABILITY FOUND] {f['title']}\n"
                
                test_case.logs += f"Scanner {scanner.scan_id} finished. Findings: {len(findings)}\n"
            except Exception as e:
                err_msg = f"Error in scanner {scanner.scan_id}: {str(e)}\n"
                test_case.logs += err_msg
                logger.error(err_msg.strip())

        test_case.status = CaseStatus.EXECUTED
        test_case.logs += f"[{datetime.utcnow().time()}] All ZAP scans for case finished.\n"
        self.db.commit()

    def _report_zap_finding(self, case: DynamicTestCase, zap_finding: dict):
        """Map ZAP-python finding to APEX DynamicFinding model."""
        # Map Severities
        sev_map = {
            "Critical": Severity.CRITICAL,
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
            "Info": Severity.INFO
        }
        severity = sev_map.get(zap_finding.get('severity'), Severity.INFO)
        
        cvss = ReportManager.get_cvss_score(case.check_type, severity)
        remediation = ReportManager.get_remediation(case.check_type)

        finding = DynamicFinding(
            session_id=case.session_id,
            test_case_id=case.id,
            endpoint_path=case.endpoint_path,
            method=case.method,
            check_type=case.check_type,
            title=zap_finding.get('title', 'ZAP Finding'),
            description=zap_finding.get('description', ''),
            severity=severity,
            cvss_score=cvss,
            remediation=remediation
        )
        self.db.add(finding)
        self.db.commit()
        self.db.refresh(finding)

        if zap_finding.get('evidence'):
            evidence = DynamicEvidence(
                finding_id=finding.id,
                request_dump="See logs for payload details",
                response_dump=str(zap_finding.get('evidence'))
            )
            self.db.add(evidence)
            self.db.commit()

    async def close(self):
        pass
