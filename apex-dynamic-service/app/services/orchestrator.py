import logging
import asyncio
import json
from datetime import datetime
from sqlalchemy.orm import Session

from app.models.dynamic import (
    DynamicTestSession, DynamicTestCase, StaticSpec, 
    SessionStatus, CaseStatus, CheckType
)
from app.services.engine import AttackEngine

logger = logging.getLogger(__name__)

class SessionOrchestrator:
    def __init__(self, db: Session):
        self.db = db

    def create_session(self, spec_id: str, target_url: str, auth_token: str = None, auth_token_secondary: str = None) -> DynamicTestSession:
        spec = self.db.query(StaticSpec).filter(StaticSpec.id == spec_id).first()
        if not spec:
            raise ValueError("Spec not found")

        session = DynamicTestSession(
            spec_id=spec_id,
            target_base_url=target_url,
            auth_token=auth_token,
            auth_token_secondary=auth_token_secondary,
            status=SessionStatus.PENDING
        )
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return session

    async def run_scan_background(self, session_id: str):
        logger.info(f"Starting Scan Session {session_id}")
        
        session = self.db.query(DynamicTestSession).filter(DynamicTestSession.id == session_id).first()
        if not session:
            logger.error(f"Session {session_id} not found during execution")
            return

        try:
            session.status = SessionStatus.RUNNING
            session.started_at = datetime.utcnow()
            self.db.commit()

            spec = session.spec
            if not spec.blueprint_json:
                logger.warning("No blueprint found. Skipping test generation.")
                session.status = SessionStatus.COMPLETED
                session.finished_at = datetime.utcnow()
                self.db.commit()
                return

            blueprint = json.loads(spec.blueprint_json)
            endpoints = blueprint.get("endpoints", [])
            
            scan_details = json.loads(spec.scan_details_json or "{}")
            static_endpoints = scan_details.get("endpoints", [])
            
            queued_cases = set()

            # 1. Static Verification
            for ep_data in static_endpoints:
                path = ep_data.get("path")
                if " " in path:
                    _, path = path.split(" ", 1)

                vulns = ep_data.get("vulnerabilities", [])
                for v in vulns:
                    rule_id = v.get("id")
                    method = v.get("method", "GET").upper()
                    
                    check_type = None
                    if "auth" in rule_id or "security" in rule_id:
                        check_type = CheckType.BROKEN_AUTH
                    elif "bola" in rule_id or "idor" in rule_id:
                        check_type = CheckType.BOLA
                    elif "sqli" in rule_id or "sql-injection" in rule_id:
                        check_type = CheckType.SQLI
                    elif "ssrf" in rule_id:
                        check_type = CheckType.SSRF
                    elif "injection" in rule_id or "command-injection" in rule_id:
                        check_type = CheckType.INJECTION
                    
                    if check_type:
                        key = (path, method, check_type)
                        if key not in queued_cases:
                            tc = DynamicTestCase(
                                session_id=session.id,
                                endpoint_path=path,
                                method=method,
                                check_type=check_type,
                                status=CaseStatus.QUEUED
                            )
                            self.db.add(tc)
                            queued_cases.add(key)

            # 2. Heuristic Discovery
            PUBLIC_PATHS = ["/login", "/register", "/auth", "/health", "/docs", "/openapi.json"]

            for ep in endpoints:
                path = ep.get("path")
                if " " in path:
                    _, path = path.split(" ", 1)
                method = ep.get("method").upper()
                
                # Logic 1: Broken Authentication
                is_public = any(p in path.lower() for p in PUBLIC_PATHS)
                if not is_public:
                    key = (path, method, CheckType.BROKEN_AUTH)
                    if key not in queued_cases:
                        self.db.add(DynamicTestCase(
                            session_id=session.id, endpoint_path=path, method=method,
                            check_type=CheckType.BROKEN_AUTH, status=CaseStatus.QUEUED
                        ))
                        queued_cases.add(key)

                # Logic 2: BOLA (IDOR)
                if "{" in path and "}" in path:
                     key = (path, method, CheckType.BOLA)
                     if key not in queued_cases:
                         self.db.add(DynamicTestCase(
                            session_id=session.id, endpoint_path=path, method=method,
                            check_type=CheckType.BOLA, status=CaseStatus.QUEUED
                         ))
                         queued_cases.add(key)

                # Logic 3: SQLi / SSRF / Injection (Heuristic)
                if ep.get("params") or ep.get("schema"):
                    for ct in [CheckType.SQLI, CheckType.SSRF, CheckType.INJECTION]:
                        key = (path, method, ct)
                        if key not in queued_cases:
                            self.db.add(DynamicTestCase(
                                session_id=session.id, endpoint_path=path, method=method,
                                check_type=ct, status=CaseStatus.QUEUED
                            ))
                            queued_cases.add(key)
            
            self.db.commit()

            # 3. Execute Attack Engine
            engine = AttackEngine(session.id, self.db)
            cases = self.db.query(DynamicTestCase).filter(
                DynamicTestCase.session_id == session.id,
                DynamicTestCase.status == CaseStatus.QUEUED
            ).all()

            logger.info(f"Generated {len(cases)} test cases. Starting execution...")

            for case in cases:
                try:
                    await engine.run_test_case(case, session.target_base_url, session.auth_token)
                except Exception as e:
                    logger.error(f"Failed to execute test case {case.id}: {e}")
                    case.status = CaseStatus.FAILED
                    case.logs = (case.logs or "") + f"\nCRITICAL ERROR: {str(e)}"
                    self.db.commit()

            await engine.close()

            # 4. Finalize
            session.status = SessionStatus.COMPLETED
            session.finished_at = datetime.utcnow()
            self.db.commit()
            logger.info(f"Scan Session {session_id} COMPLETED")

        except Exception as e:
            logger.error(f"Fatal error in SessionOrchestrator: {e}")
            session.status = SessionStatus.FAILED
            session.finished_at = datetime.utcnow()
            self.db.commit()
            raise
