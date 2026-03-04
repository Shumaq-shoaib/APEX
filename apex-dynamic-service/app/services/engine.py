import logging
import asyncio
import io
import contextlib
import json
from datetime import datetime
from sqlalchemy.orm import Session
from app.models.dynamic import DynamicTestCase, CaseStatus, DynamicTestSession, SessionStatus, CheckType, Severity, DynamicFinding, DynamicEvidence
from app.services.reporting import ReportManager

try:
    from app.scanner_core.context import ScanContext, AuthConfig
    from app.scanners.base import BaseScanner
except ImportError as e:
    logging.error(f"Failed to import APEX scanners: {e}")

# Configure logging
logger = logging.getLogger(__name__)

class AttackEngine:
    def __init__(self, session_id: str, db_session: Session):
        self.session_id = session_id
        self.db = db_session
        self.scanners = []
        self._load_scanners()
        if not self.scanners:
            logger.error(f"CRITICAL: No scanners loaded for session {session_id}!")

    def _load_scanners(self):
        """Load all scanners dynamically."""
        import importlib
        import pkgutil
        import app.scanners as scanners_pkg
        from inspect import isclass

        # Create a dummy context for initialization
        dummy_context = ScanContext(target_url="http://localhost")
        
        try:
            package = scanners_pkg
            prefix = package.__name__ + "."
            for _, name, _ in pkgutil.iter_modules(package.__path__, prefix):
                if name == "app.scanners.base":
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
                            logger.info(f"Loaded Scanner: {scanner_instance.name} [{scanner_instance.scan_id}]")
                except Exception as e:
                    logger.error(f"Failed to load scanner from {name}: {e}")
        except Exception as e:
            logger.error(f"Failed to iterate scanners: {e}")

    def _get_scanners_for_check(self, check_type: CheckType) -> list:
        """Map APEX CheckType to Scanners."""
        mapping = {
            CheckType.BOLA: ["APEX-IDOR-ACTIVE"],
            CheckType.BROKEN_AUTH: ["APEX-JWT", "APEX-SEC-HEADERS", "APEX-BROKEN-AUTH"],
            CheckType.SQLI: ["APEX-SQLI"],
            CheckType.INJECTION: ["APEX-CMD-INJ"],
            CheckType.SSRF: ["APEX-SSRF"],
            CheckType.DATA_EXPOSURE: ["APEX-IDOR-PASSIVE", "APEX-MASS-ASSIGN"],
            CheckType.XSS: ["APEX-XSS"],
            CheckType.OTHER: ["APEX-REDIRECT", "APEX-XXE"],
            CheckType.CORS: ["APEX-CORS"],
            CheckType.CSRF: ["APEX-CSRF"],
            CheckType.CRLF: ["APEX-CRLF"],
            CheckType.RATE_LIMIT: ["APEX-RATE-LIMIT"],
            CheckType.SSTI: ["APEX-SSTI"],
        }
        target_ids = mapping.get(check_type, [])
        return [s for s in self.scanners if s.scan_id in target_ids]

    async def run_test_case(self, test_case: DynamicTestCase, target_base_url: str, auth_token: str | None = None):
        """
        Executes ZAP-python scanners against the target for the given test case.
        """
        full_url = f"{target_base_url.rstrip('/')}{test_case.endpoint_path}"
        method = test_case.method.upper()
        
        start_msg = f"[{datetime.utcnow().time()}] Starting APEX {test_case.check_type} on {method} {full_url} ...\n"
        test_case.logs = (test_case.logs or "") + start_msg
        self.db.commit()

        # 1. Get Blueprint to find endpoint metadata
        session = self.db.query(DynamicTestSession).get(self.session_id)

        # Initialize Scan Context
        sec_token = session.auth_token_secondary if session else None
        scan_context = ScanContext(
            target_url=target_base_url,
            auth=AuthConfig(
                token=auth_token.split(" ")[1] if auth_token and " " in auth_token else auth_token,
                secondary_token=sec_token.split(" ")[1] if sec_token and " " in sec_token else sec_token
            )
        )

        blueprint = json.loads(session.spec.blueprint_json) if session and session.spec and session.spec.blueprint_json else {}
        endpoints = blueprint.get("endpoints", [])
        
        # Find matching endpoint in blueprint
        endpoint_meta = next(
            (ep for ep in endpoints if ep.get("path") == test_case.endpoint_path and ep.get("method") == method), 
            {"params": [], "schema": {}, "example": {}}
        )

        relevant_scanners = self._get_scanners_for_check(test_case.check_type)
        
        if not relevant_scanners:
            msg = f"[{datetime.utcnow().time()}] No scanners mapped for {test_case.check_type}. Skipping.\n"
            test_case.logs = (test_case.logs or "") + msg
            test_case.status = CaseStatus.SKIPPED
            self.db.commit()
            return

        total_findings_count = 0
        for scanner in relevant_scanners:
            scanner.context = scan_context
            scanner.results = []
            
            scanner_msg = f"[{datetime.utcnow().strftime('%H:%M:%S')}] --- Running Scanner: {scanner.name} [{scanner.scan_id}] ---\n"
            test_case.logs = (test_case.logs or "") + scanner_msg
            self.db.commit()

            try:
                log_handler = _TestCaseLogHandler(test_case, self.db)
                scanner_logger = logging.getLogger(f"scanners.{scanner.scan_id.lower().replace('-', '_')}")
                scanner_logger.addHandler(log_handler)

                findings = await asyncio.to_thread(
                    scanner.run, 
                    test_case.endpoint_path, 
                    method, 
                    endpoint_meta
                )

                scanner_logger.removeHandler(log_handler)
                
                if findings:
                    for f in findings:
                        self._report_finding(test_case, f)
                        sev = f.get('severity', 'Info')
                        test_case.logs += f"  [!] VULNERABILITY: {f['title']} (Severity: {sev})\n"
                        total_findings_count += 1
                
                test_case.logs += f"  Scanner {scanner.name}: {len(findings)} finding(s)\n"
            except Exception as e:
                err_msg = f"  [ERROR] Scanner {scanner.scan_id}: {str(e)}\n"
                test_case.logs += err_msg
                logger.error(err_msg.strip())

        test_case.status = CaseStatus.EXECUTED
        test_case.logs += f"[{datetime.utcnow().strftime('%H:%M:%S')}] Completed — {total_findings_count} vulnerability(ies) found.\n"
        self.db.commit()

    def _report_finding(self, case: DynamicTestCase, finding: dict):
        """Map finding to APEX DynamicFinding model."""
        sev_map = {
            "Critical": Severity.CRITICAL,
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
            "Info": Severity.INFO
        }
        severity = sev_map.get(finding.get('severity'), Severity.INFO)
        
        cvss = ReportManager.get_cvss_score(case.check_type, severity)
        remediation = ReportManager.get_remediation(case.check_type)

        new_finding = DynamicFinding(
            session_id=case.session_id,
            test_case_id=case.id,
            endpoint_path=case.endpoint_path,
            method=case.method,
            check_type=case.check_type,
            title=finding.get('title', 'APEX Finding'),
            description=finding.get('description', ''),
            severity=severity,
            cvss_score=cvss,
            remediation=remediation
        )
        self.db.add(new_finding)
        self.db.commit()
        self.db.refresh(new_finding)

        request_dump = finding.get('request_dump', '')
        response_dump = finding.get('response_dump', '')

        if not request_dump and not response_dump and finding.get('evidence'):
            response_dump = str(finding['evidence'])

        if request_dump or response_dump:
            evidence = DynamicEvidence(
                finding_id=new_finding.id,
                request_dump=request_dump or None,
                response_dump=response_dump or None
            )
            self.db.add(evidence)
            self.db.commit()

    async def close(self):
        pass


class _TestCaseLogHandler(logging.Handler):
    """Captures scanner log output and appends it to the test case logs column."""
    def __init__(self, test_case: DynamicTestCase, db: Session):
        super().__init__(level=logging.DEBUG)
        self.test_case = test_case
        self.db = db

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            self.test_case.logs = (self.test_case.logs or "") + f"  {msg}\n"
            self.db.commit()
        except Exception:
            pass
