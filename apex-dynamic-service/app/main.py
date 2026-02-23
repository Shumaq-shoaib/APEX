import sys
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.api import deps
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.api import deps
from app.core import config
from app.core.logging import setup_logging

# Initialize Logging
setup_logging()
import os
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Add Static Analysis to path
static_analysis_src = os.path.join(project_root, "static_analysis", "src")
if static_analysis_src not in sys.path:
    sys.path.append(static_analysis_src)

# Add ZAP-python to path for dynamic scanning modules
# In Docker, ZAP-python is mounted at /ZAP-python; locally it's relative to project root
zap_python_path = "/ZAP-python" if os.path.isdir("/ZAP-python") else os.path.join(project_root, "ZAP-python")
if zap_python_path not in sys.path:
    sys.path.append(zap_python_path)

# Import Routes (Now safe to import)
from app.api.routes import specs, sessions

# Import DB for Startup Creation
from app.db.base import Base
from app.db.session import engine

app = FastAPI(
    title="APEX Dynamic Analysis Service",
    version=config.VERSION,
    description="Microservice for dynamic API security testing (DAST) and Static Analysis Gateway."
)

@app.on_event("startup")
def create_tables():
    Base.metadata.create_all(bind=engine)

    return {
        "status": "online",
        "service": "APEX Dynamic Analysis Service",
        "message": "Visit /docs for API documentation"
    }

# -----------------------------------------------------------------------------
# 2. Middleware
# -----------------------------------------------------------------------------
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.core.limiter import limiter

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# 3. Router Mounting
# -----------------------------------------------------------------------------
# New RESTful API for Specifications
app.include_router(specs.router, prefix="/api/specs", tags=["Specs"])
app.include_router(sessions.router, prefix="/api/sessions", tags=["Sessions"])

# Legacy /analyze Endpoint (Compatibility for Dashboard Phase 0)
# Redirects logic to the new persisted spec flow.
app.add_api_route(
    "/analyze", 
    specs.upload_and_analyze_spec, 
    methods=["POST"], 
    include_in_schema=False,
    tags=["Legacy"]
)

# -----------------------------------------------------------------------------
# 4. Global Endpoints
# -----------------------------------------------------------------------------
@app.get("/health", tags=["Health"])
def health_check(db: Session = Depends(deps.get_db)):
    # 1. Check Database
    db_status = "unknown"
    try:
        # Simple query to check connection
        db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as e:
        db_status = f"disconnected: {str(e)}"

    # 2. Check Scanner
    scanner_status = "available" if specs.SCANNER_AVAILABLE else "unavailable"

    # 3. Determine Overall Status
    overall_status = "healthy"
    if db_status != "connected" or scanner_status != "available":
        overall_status = "degraded"

    return {
        "status": overall_status,
        "components": {
            "database": db_status,
            "scanner": scanner_status
        },
        "version": config.VERSION
    }
