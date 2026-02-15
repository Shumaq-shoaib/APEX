import sys
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core import config

# -----------------------------------------------------------------------------
# 1. Path Setup for Modules
# -----------------------------------------------------------------------------
import os
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Add Static Analysis to path
static_analysis_src = os.path.join(project_root, "static_analysis", "src")
if static_analysis_src not in sys.path:
    sys.path.append(static_analysis_src)

# Add ZAP-python to path for dynamic scanning modules
zap_python_path = os.path.join(project_root, "ZAP-python")
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

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "APEX Dynamic Analysis Service",
        "message": "Visit /docs for API documentation"
    }

@app.get("/health")
def health_check():
    return {"status": "ok"}

# -----------------------------------------------------------------------------
# 2. Middleware
# -----------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
@app.get("/health")
def health_check():
    return {
        "status": "ok", 
        "service": "apex-dynamic-service", 
        "scanner_available": specs.SCANNER_AVAILABLE
    }
