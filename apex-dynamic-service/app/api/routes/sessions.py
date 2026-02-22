from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status, UploadFile, File, Form
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel, field_validator, HttpUrl
import json
import os
from datetime import datetime

from app.api import deps
from app.models.dynamic import DynamicTestSession, SessionStatus, StaticSpec
from app.services.orchestrator import SessionOrchestrator
from app.services.direct_parser import DirectOASParser
from fastapi import Request
from app.core.limiter import limiter

router = APIRouter()

# Pydantic Schemas
class SessionCreate(BaseModel):
    spec_id: str
    target_url: HttpUrl
    auth_token: Optional[str] = None

    # Removed manual field_validator for target_url as HttpUrl handles it
    
    @field_validator('auth_token')
    @classmethod
    def validate_token_length(cls, v: str) -> str:
        if v and len(v) > 10000: # Max 10KB token
             raise ValueError('Auth token is too large')
        return v

class FindingResponse(BaseModel):
    id: str
    test_case_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: str
    cvss_score: float = 0.0
    remediation: Optional[str] = None
    check_type: str
    class Config:
        from_attributes = True # V2 compat

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
    created_at: str = None
    findings: List[FindingResponse] = []
    test_cases: List[TestCaseResponse] = []

    class Config:
        from_attributes = True

@router.post("/", response_model=SessionResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
def create_session(
    request: Request,
    payload: SessionCreate, 
    db: Session = Depends(deps.get_db)
):
    """
    Initialize a new Dynamic Analysis Session.
    """
    orch = SessionOrchestrator(db)
    try:
        # Pydantic HttpUrl needs to be converted to str for logic
        session = orch.create_session(payload.spec_id, str(payload.target_url), payload.auth_token)
        return session
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/direct", response_model=SessionResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("2/minute")
async def create_direct_session(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    target_url: str = Form(...),
    auth_token: Optional[str] = Form(None),
    auth_token_secondary: Optional[str] = Form(None),
    db: Session = Depends(deps.get_db)
):
    """
    Directly start a dynamic scan from an OpenAPI file (Bypassing Static Audit).
    """
    # -1. Validate Inputs
    try:
        from pydantic import TypeAdapter, HttpUrl
        TypeAdapter(HttpUrl).validate_python(target_url)
    except Exception:
         # Fallback or specific error if Pydantic fails, but we rely on it
        raise HTTPException(status_code=400, detail="Invalid URL. Must be a valid HTTP/HTTPS URL.")
    
    if auth_token and len(auth_token) > 10000:
        raise HTTPException(status_code=400, detail="Auth token is too large")

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
    # Must populate minimal structure to avoid frontend crashes
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
        auth_token=auth_token,
        auth_token_secondary=auth_token_secondary
    )
    
    # Auto-start
    background_tasks.add_task(run_scan_wrapper, session.id)
    
    return session

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
    # Verify session exists first
    session = db.query(DynamicTestSession).filter(DynamicTestSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if session.status != SessionStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Session is in {session.status} state, cannot start.")

    # Run in background
    # Note: We need to instantiate Orchestrator with a DB session that is thread-safe or created within the task.
    # Passing the request-scoped 'db' to background task is risky because it might be closed.
    # STARTING A NEW DB SESSION INSIDE THE TASK IS BETTER. 
    # But for now, let's rely on the simple injection, if it fails we fix it.
    # Actually, preventing 'Session is closed' error:
    # We will pass the ID and let the Orchestrator create its own session? 
    # No, Orchestrator takes `db`. 
    # Let's update `start_session` to NOT pass `orch.run_scan_background` directly if `db` is closed.
    # Better: Use a wrapper function that creates a new SessionLocal.
    
    background_tasks.add_task(run_scan_wrapper, session_id)
    return {"message": "Scan started in background", "session_id": session_id}

# Helper for Background Task with fresh DB session
from app.db.session import SessionLocal

async def run_scan_wrapper(session_id: str):
    db = SessionLocal()
    try:
        orch = SessionOrchestrator(db)
        await orch.run_scan_background(session_id)
    finally:
        db.close()


@router.get("/{session_id}", response_model=SessionResponse)
def get_session(session_id: str, db: Session = Depends(deps.get_db)):
    """
    Get session status.
    """
    session = db.query(DynamicTestSession).filter(DynamicTestSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session
