from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status, UploadFile, File, Form
from sqlalchemy.orm import Session, joinedload, subqueryload
from typing import List, Optional
from pydantic import BaseModel, field_validator, HttpUrl
import json
import os
from datetime import datetime

from app.api import deps
from app.models.dynamic import DynamicTestSession, DynamicFinding, SessionStatus, StaticSpec
from app.services.orchestrator import SessionOrchestrator
from app.services.direct_parser import DirectOASParser
from fastapi import Request
from app.core.limiter import limiter

router = APIRouter()

# ─── Pydantic Schemas ──────────────────────────────────────────────────

class SessionCreate(BaseModel):
    spec_id: str
    target_url: HttpUrl

    # Automated Auth Credentials
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    auth_sec_username: Optional[str] = None
    auth_sec_password: Optional[str] = None

    # Advanced Overrides
    auth_login_endpoint: Optional[str] = None
    auth_username_field: Optional[str] = None
    auth_token_path: Optional[str] = None
    concurrency_limit: int = 5

class EvidenceResponse(BaseModel):
    request_dump: Optional[str] = None
    response_dump: Optional[str] = None
    class Config:
        from_attributes = True

class FindingResponse(BaseModel):
    id: str
    test_case_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: str
    cvss_score: float = 0.0
    remediation: Optional[str] = None
    check_type: str
    endpoint_path: Optional[str] = None
    method: Optional[str] = None
    evidence: Optional[EvidenceResponse] = None
    class Config:
        from_attributes = True

class TestCaseResponse(BaseModel):
    id: str
    endpoint_path: str
    method: str
    check_type: str
    status: str
    rule_id: Optional[str] = None
    logs: Optional[str] = None
    class Config:
        from_attributes = True

class SessionResponse(BaseModel):
    id: str
    spec_id: str
    target_base_url: str
    status: SessionStatus
    error_message: Optional[str] = None
    findings: List[FindingResponse] = []
    test_cases: List[TestCaseResponse] = []

    class Config:
        from_attributes = True


# ─── Route: Standard Session (from existing static spec) ──────────────

@router.post("/", response_model=SessionResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
def create_session(
    request: Request,
    payload: SessionCreate, 
    db: Session = Depends(deps.get_db)
):
    """
    Initialize a new Dynamic Analysis Session.
    Accepts username/password credentials for automated authentication.
    """
    orch = SessionOrchestrator(db)
    try:
        session = orch.create_session(
            spec_id=payload.spec_id,
            target_url=str(payload.target_url),
            auth_username=payload.auth_username,
            auth_password=payload.auth_password,
            auth_sec_username=payload.auth_sec_username,
            auth_sec_password=payload.auth_sec_password,
            auth_login_endpoint=payload.auth_login_endpoint,
            auth_username_field=payload.auth_username_field,
            auth_token_path=payload.auth_token_path,
            concurrency_limit=payload.concurrency_limit,
        )
        return session
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ─── Route: Direct Session (upload spec + start scan) ─────────────────

@router.post("/direct", response_model=SessionResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("2/minute")
async def create_direct_session(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    target_url: str = Form(...),
    auth_username: Optional[str] = Form(None),
    auth_password: Optional[str] = Form(None),
    auth_sec_username: Optional[str] = Form(None),
    auth_sec_password: Optional[str] = Form(None),
    auth_login_endpoint: Optional[str] = Form(None),
    auth_username_field: Optional[str] = Form(None),
    auth_token_path: Optional[str] = Form(None),
    enable_crawl: Optional[str] = Form("false"),
    concurrency_limit: int = Form(5),
    db: Session = Depends(deps.get_db)
):
    """
    Directly start a dynamic scan from an OpenAPI file (Bypassing Static Audit).
    Accepts username/password credentials for automated authentication.
    """
    # -1. Validate Inputs
    try:
        from pydantic import TypeAdapter, HttpUrl
        TypeAdapter(HttpUrl).validate_python(target_url)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL. Must be a valid HTTP/HTTPS URL.")

    # 0. Validate Extension
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in [".json", ".yaml", ".yml"]:
        raise HTTPException(status_code=400, detail="Invalid file type. Only .json, .yaml, .yml are allowed.")

    # 1. Parse content & Validate Size
    MAX_FILE_SIZE = 10 * 1024 * 1024 # 10MB
    content = await file.read()
    
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large. Max size is 10MB.")
    try:
        parser = DirectOASParser(content, file.filename)
        blueprint = parser.generate_blueprint()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid OpenAPI Spec: {str(e)}")

    # 2. Create 'Virtual' Static Spec
    minimal_details = {
        "metadata": {
            "api_title": "Direct Scan",
            "api_version": "1.0",
            "file_analyzed": file.filename,
            "timestamp_utc": datetime.utcnow().isoformat(),
            "profile_used": "direct",
            "server_url": target_url
        },
        "summary": {
            "total": 0, 
            "Critical": 0, 
            "High": 0, 
            "Medium": 0, 
            "Low": 0, 
            "Informational": 0
        },
        "endpoints": []
    }

    spec = StaticSpec(
        filename=f"Direct Scan: {file.filename}",
        blueprint_json=json.dumps(blueprint),
        scan_details_json=json.dumps(minimal_details)
    )
    db.add(spec)
    db.commit()
    db.refresh(spec)

    # 3. Create Session & Start
    orch = SessionOrchestrator(db)
    session = orch.create_session(
        spec_id=spec.id,
        target_url=target_url,
        auth_username=auth_username,
        auth_password=auth_password,
        auth_sec_username=auth_sec_username,
        auth_sec_password=auth_sec_password,
        auth_login_endpoint=auth_login_endpoint,
        auth_username_field=auth_username_field,
        auth_token_path=auth_token_path,
        enable_crawl=enable_crawl or "false",
        concurrency_limit=concurrency_limit,
    )
    
    # Auto-start
    background_tasks.add_task(run_scan_wrapper, session.id)
    
    return session


# ─── Route: Quick Scan (URL only, no spec) ────────────────────────────

class QuickScanCreate(BaseModel):
    target_url: HttpUrl
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    auth_sec_username: Optional[str] = None
    auth_sec_password: Optional[str] = None
    auth_login_endpoint: Optional[str] = None
    auth_username_field: Optional[str] = None
    auth_token_path: Optional[str] = None
    concurrency_limit: int = 5

@router.post("/quick", response_model=SessionResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def create_quick_session(
    request: Request,
    payload: QuickScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(deps.get_db)
):
    """
    Start a dynamic scan with only a target URL (no spec file required).
    Generates a minimal placeholder spec so the orchestrator can run heuristic discovery.
    """
    from urllib.parse import urlparse
    parsed = urlparse(str(payload.target_url))
    host_label = parsed.hostname or "target"

    empty_blueprint = {"endpoints": [], "info": {"title": f"Quick Scan: {host_label}"}}
    minimal_details = {
        "metadata": {
            "api_title": f"Quick Scan: {host_label}",
            "api_version": "1.0",
            "file_analyzed": "none (URL-only scan)",
            "timestamp_utc": datetime.utcnow().isoformat(),
            "profile_used": "quick",
            "server_url": str(payload.target_url)
        },
        "summary": {"total": 0, "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0},
        "endpoints": []
    }

    spec = StaticSpec(
        filename=f"Quick Scan: {host_label}",
        blueprint_json=json.dumps(empty_blueprint),
        scan_details_json=json.dumps(minimal_details)
    )
    db.add(spec)
    db.commit()
    db.refresh(spec)

    orch = SessionOrchestrator(db)
    session = orch.create_session(
        spec_id=spec.id,
        target_url=str(payload.target_url),
        auth_username=payload.auth_username,
        auth_password=payload.auth_password,
        auth_sec_username=payload.auth_sec_username,
        auth_sec_password=payload.auth_sec_password,
        auth_login_endpoint=payload.auth_login_endpoint,
        auth_username_field=payload.auth_username_field,
        auth_token_path=payload.auth_token_path,
        concurrency_limit=payload.concurrency_limit,
    )

    background_tasks.add_task(run_scan_wrapper, session.id)
    return session


# ─── Route: Start a PENDING Session ───────────────────────────────────

@router.post("/{session_id}/start", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("10/minute")
async def start_session(
    request: Request,
    session_id: str, 
    background_tasks: BackgroundTasks,
    db: Session = Depends(deps.get_db)
):
    """
    Start the scan execution in the background.
    """
    session = db.query(DynamicTestSession).filter(DynamicTestSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if session.status != SessionStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Session is in {session.status} state, cannot start.")

    background_tasks.add_task(run_scan_wrapper, session_id)
    return {"message": "Scan started in background", "session_id": session_id}


# ─── Background Task Helper ──────────────────────────────────────────

from app.db.session import SessionLocal

def run_scan_wrapper(session_id: str):
    db = SessionLocal()
    try:
        orch = SessionOrchestrator(db)
        import asyncio
        asyncio.run(orch.run_scan_background(session_id))
    finally:
        db.close()


# ─── Route: Get Session by Spec ID ─────────────────────────────────────

@router.get("/by_spec/{spec_id}", response_model=SessionResponse)
def get_session_by_spec(spec_id: str, db: Session = Depends(deps.get_db)):
    """
    Get the most recent session associated with a specific static spec.
    """
    session = db.query(DynamicTestSession).options(
        subqueryload(DynamicTestSession.findings).joinedload(DynamicFinding.evidence),
        subqueryload(DynamicTestSession.test_cases)
    ).filter(DynamicTestSession.spec_id == spec_id).order_by(DynamicTestSession.id.desc()).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found for this spec")
    return session


# ─── Route: Get Session Status ────────────────────────────────────────

@router.get("/{session_id}", response_model=SessionResponse)
def get_session(session_id: str, db: Session = Depends(deps.get_db)):
    """
    Get session status with findings, evidence, and test cases eagerly loaded.
    """
    session = db.query(DynamicTestSession).options(
        subqueryload(DynamicTestSession.findings).joinedload(DynamicFinding.evidence),
        subqueryload(DynamicTestSession.test_cases)
    ).filter(DynamicTestSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


# ─── Route: Stop Session ──────────────────────────────────────────────

@router.post("/{session_id}/stop")
def stop_session(session_id: str, db: Session = Depends(deps.get_db)):
    """
    Cancel an active dynamic scan session.
    """
    session = db.query(DynamicTestSession).filter(DynamicTestSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if session.status in [SessionStatus.COMPLETED, SessionStatus.FAILED, SessionStatus.CANCELLED]:
        return {"status": "already_finished", "current_status": session.status}
    
    session.status = SessionStatus.CANCELLED
    session.error_message = "Scan stopped by user."
    db.commit()
    return {"status": "cancelled"}


# ─── Route: Generate Report ──────────────────────────────────────────

@router.get("/{session_id}/report")
def get_report(session_id: str, format: str = "html", db: Session = Depends(deps.get_db)):
    """
    Generate and download a scan report as HTML or PDF.
    """
    from fastapi.responses import Response
    from app.services.report_generator import generate_html_report, generate_pdf_report

    session = db.query(DynamicTestSession).options(
        subqueryload(DynamicTestSession.findings).joinedload(DynamicFinding.evidence),
        subqueryload(DynamicTestSession.test_cases)
    ).filter(DynamicTestSession.id == session_id).first()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.status not in (SessionStatus.COMPLETED, SessionStatus.FAILED):
        raise HTTPException(status_code=400, detail="Report is only available for completed or failed scans.")

    filename_base = f"apex_report_{session_id[:8]}"

    if format == "pdf":
        pdf_bytes = generate_pdf_report(session)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename_base}.pdf"'}
        )

    html_content = generate_html_report(session)
    return Response(
        content=html_content,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename_base}.html"'}
    )
