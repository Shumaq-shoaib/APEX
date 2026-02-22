import os
import shutil
import tempfile
import json
import logging
import traceback
from datetime import datetime
from typing import Any, Dict

from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, status
from sqlalchemy.orm import Session
from app.api import deps
from app.models.dynamic import StaticSpec
from fastapi import Request
from app.core.limiter import limiter

# Try importing Backend Logic
try:
    from v6_refactor.models import OasDetails
    from v6_refactor.scanner import analyze_spec
    from v6_refactor.config import CONFIG
    from v6_refactor.rules import apply_policy_pack, spectral_ingest, VULNERABILITY_MAP, RULE_FUNCTIONS, build_yaml_rule_fn
    from v6_refactor.blueprint import generate_blueprint as gen_bp
    SCANNER_AVAILABLE = True
except ImportError:
    SCANNER_AVAILABLE = False

router = APIRouter()

@router.post("/", status_code=status.HTTP_201_CREATED)
@limiter.limit("2/minute")
async def upload_and_analyze_spec(
    file: UploadFile = File(...),
    profile: str = Form("default"),
    fail_on: str = Form("none"),
    generate_blueprint: str = Form("true"), # Default true now since we persist it
    policy_pack: UploadFile = File(None),
    spectral_in: UploadFile = File(None),
    db: Session = Depends(deps.get_db),
    request: Request = None 
):
    """
    Upload an OpenAPI file, run Static Analysis, generate a Blueprint, and Persist the Spec.
    Returns the Scan Report + Spec ID.
    """
    if not SCANNER_AVAILABLE:
        raise HTTPException(status_code=500, detail="Static Scanner module not found.")

    # 0. Validate File Extension
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in [".json", ".yaml", ".yml"]:
        raise HTTPException(status_code=400, detail="Invalid file type. Only .json, .yaml, .yml are allowed.")

    # 1. Save uploaded file temporarily & Validate Size
    MAX_FILE_SIZE = 10 * 1024 * 1024 # 10MB
    suffix = ext
    
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        # Copy and count bytes to avoid filling disk with massive files
        size = 0
        CHUNK_SIZE = 1024 * 1024 # 1MB chunks
        while True:
            chunk = await file.read(CHUNK_SIZE)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_FILE_SIZE:
                tmp.close()
                os.unlink(tmp.name)
                raise HTTPException(status_code=400, detail="File too large. Max size is 10MB.")
            tmp.write(chunk)
        tmp_path = tmp.name

    policy_path = None
    spectral_path = None

    try:
        # Handle Policy Pack
        if policy_pack:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".yaml") as pp_tmp:
                shutil.copyfileobj(policy_pack.file, pp_tmp)
                policy_path = pp_tmp.name
        
        # Handle Spectral Ruleset
        if spectral_in:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".yaml") as sp_tmp:
                shutil.copyfileobj(spectral_in.file, sp_tmp)
                spectral_path = sp_tmp.name

        # 2. Parse Spec
        try:
            with open(tmp_path, 'r', encoding='utf-8') as f:
                import yaml
                content = yaml.safe_load(f)
        except Exception as e:
             raise HTTPException(status_code=400, detail=f"Invalid spec file: {e}")

        # 3. Configure & Analyze
        CONFIG["profile"] = profile
        
        # Apply Policy Pack
        if policy_path:
            pack_info = apply_policy_pack([policy_path])
            yaml_rules = pack_info.get("yaml_rules") or []
            for ydef in yaml_rules:
                try:
                    key, meta, fn = build_yaml_rule_fn(ydef)
                    VULNERABILITY_MAP[key] = meta
                    RULE_FUNCTIONS[key] = fn
                except Exception as e:
                    logging.error(f"Invalid YAML rule {ydef}: {e}")

        # Apply Spectral
        if spectral_path:
            spectral_ingest(spectral_path)

        details = OasDetails(content)
        details.spec()["__file_path__"] = file.filename 
        
        result = analyze_spec(details)
        
        # 4. Generate Blueprint
        # Always generate internal blueprint for persistence, regardless of flag?
        # User requested GET /{id}/blueprint exposure, so we SHOULD save it.
        blueprint_data = gen_bp(details, result)

        # 5. Transform for Dashboard
        info = details.get_info() or {}
        servers = details.get_servers() or []
        default_server_url = ""
        if servers and isinstance(servers[0], dict):
             default_server_url = servers[0].get("url", "")

        transformed_summary = {
            "metadata": {
                "api_title": info.get("title", "N/A"),
                "api_version": info.get("version", "N/A"),
                "file_analyzed": file.filename,
                "timestamp_utc": datetime.utcnow().isoformat(),
                "profile_used": profile,
                "server_url": default_server_url
            },
            "summary": result.get("summary", {}),
            "endpoints": [],
            "blueprint": blueprint_data if generate_blueprint.lower() == "true" else None
        }
        
        for ep_key, data in (result.get("endpoints") or {}).items():
            vulns = data.get("vulnerabilities", [])
            mapped_vulns = []
            for v in vulns:
                mapped_v = v.copy()
                mapped_v["id"] = v.get("rule_key")
                mapped_vulns.append(mapped_v)
            
            transformed_summary["endpoints"].append({
                "path": ep_key, 
                "vulnerabilities": mapped_vulns
            })

        # 6. Persist to DB
        db_spec = StaticSpec(
            filename=file.filename,
            blueprint_json=json.dumps(blueprint_data),
            scan_details_json=json.dumps(transformed_summary)
        )
        db.add(db_spec)
        db.commit()
        db.refresh(db_spec)

        # 7. Retention Policy: Keep only the last 20 scans
        try:
            MAX_RETENTION = 20
            # Get total count
            total_count = db.query(StaticSpec).count()
            if total_count > MAX_RETENTION:
                # Calculate how many to remove
                to_remove = total_count - MAX_RETENTION
                # Find the IDs of the oldest 'to_remove' entries
                oldest_specs = db.query(StaticSpec.id)\
                    .order_by(StaticSpec.upload_date.asc())\
                    .limit(to_remove)\
                    .all()
                
                # Delete them
                for (old_id,) in oldest_specs:
                    db.query(StaticSpec).filter(StaticSpec.id == old_id).delete(synchronize_session=False)
                
                db.commit()
                logging.info(f"Retention Policy: Cleaned up {to_remove} old scans.")
        except Exception as cleanup_err:
            logging.error(f"Retention Policy Failure: {cleanup_err}")
            # Do not fail request if cleanup fails

        # Attach ID to response
        transformed_summary["spec_id"] = str(db_spec.id)
            
        return transformed_summary

    except Exception as e:
        # Standardized Error Handling
        # Ensure we don't leak internals to client, but log full trace
        try:
            logging.error(f"Analysis error: {traceback.format_exc()}")
        except:
            pass # Fallback if logging fails
            
        raise HTTPException(
            status_code=500, 
            detail={
                "error": "Analysis Execution Failed",
                "message": "An internal error occurred while processing the specification. Please check server logs.",
                "code": "INTERNAL_ANALYSIS_ERROR"
            }
        )
        
    finally:
        if os.path.exists(tmp_path): os.unlink(tmp_path)
        if policy_path and os.path.exists(policy_path): os.unlink(policy_path)
        if spectral_path and os.path.exists(spectral_path): os.unlink(spectral_path)


@router.get("/", response_model=list[dict])
def list_specs(skip: int = 0, limit: int = 100, db: Session = Depends(deps.get_db)):
    """
    List all uploaded specs with metadata.
    """
    specs = db.query(StaticSpec).order_by(StaticSpec.upload_date.desc()).offset(skip).limit(limit).all()
    return [
        {
            "id": spec.id,
            "filename": spec.filename,
            "upload_date": spec.upload_date,
            "api_title": json.loads(spec.scan_details_json).get("metadata", {}).get("api_title", "N/A") if spec.scan_details_json else "N/A"
        }
        for spec in specs
    ]

@router.get("/{spec_id}/blueprint")
def get_spec_blueprint(spec_id: str, db: Session = Depends(deps.get_db)):
    """
    Retrieve the generated Scan Blueprint for a specific scan.
    Used by the Dynamic Engine to initialize test sessions.
    """
    spec = db.query(StaticSpec).filter(StaticSpec.id == spec_id).first()
    if not spec:
        raise HTTPException(status_code=404, detail="Spec not found")
    
    if not spec.blueprint_json:
        raise HTTPException(status_code=404, detail="No blueprint available for this spec")
        
    return json.loads(spec.blueprint_json)

@router.get("/{spec_id}")
def get_spec_details(spec_id: str, db: Session = Depends(deps.get_db)):
    """
    Retrieve the full scan report for a spec.
    """
    spec = db.query(StaticSpec).filter(StaticSpec.id == spec_id).first()
    if not spec:
        raise HTTPException(status_code=404, detail="Spec not found")
    
    if not spec.scan_details_json:
        raise HTTPException(status_code=404, detail="No scan details available")
        
    details = json.loads(spec.scan_details_json)
    
    # Check for existing dynamic session
    session = db.query(StaticSpec).get(spec_id).sessions
    # This relationship returns a list. Get the latest one.
    # We need to sort or just take the last one.
    # Ideally, we should order by started_at desc.
    # Relationship in StaticSpec is: sessions = relationship("DynamicTestSession", back_populates="spec")
    
    # Improved query
    from app.models.dynamic import DynamicTestSession
    latest_session = db.query(DynamicTestSession).filter(DynamicTestSession.spec_id == spec_id).order_by(DynamicTestSession.started_at.desc()).first()
    
    if latest_session:
        details["dynamic_session_id"] = latest_session.id
        
    details["spec_id"] = spec_id
    return details

@router.delete("/{spec_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_spec(spec_id: str, db: Session = Depends(deps.get_db)):
    """
    Delete a spec and all associated data.
    """
    spec = db.query(StaticSpec).filter(StaticSpec.id == spec_id).first()
    if not spec:
        raise HTTPException(status_code=404, detail="Spec not found")
        
    db.delete(spec)
    db.commit()
    return None
