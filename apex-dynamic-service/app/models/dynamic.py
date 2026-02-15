import uuid
import enum
from datetime import datetime
from sqlalchemy import Column, String, Float, Text, DateTime, ForeignKey, CHAR, Enum as SqlEnum
# Removed LONGTEXT for SQLite compatibility
from sqlalchemy.orm import relationship
from app.db.base_class import Base

# Enums
class SessionStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class CaseStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    EXECUTED = "EXECUTED"
    SKIPPED = "SKIPPED"

class CheckType(str, enum.Enum):
    BOLA = "BOLA"
    BROKEN_AUTH = "BROKEN_AUTH"
    DATA_EXPOSURE = "DATA_EXPOSURE"
    SQLI = "SQLI"
    XSS = "XSS"
    SSRF = "SSRF"
    INJECTION = "INJECTION"
    OTHER = "OTHER"

class Severity(str, enum.Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

def generate_uuid():
    return str(uuid.uuid4())

class StaticSpec(Base):
    __tablename__ = "static_spec"

    id = Column(CHAR(36), primary_key=True, default=generate_uuid)
    filename = Column(String(255), nullable=False)
    upload_date = Column(DateTime, default=datetime.utcnow)
    
    # Large JSON blobs - Use LONGTEXT (4GB) instead of TEXT (64KB)
    blueprint_json = Column(Text, nullable=True) 
    scan_details_json = Column(Text, nullable=True) # Full static report

    # Relationships
    sessions = relationship("DynamicTestSession", back_populates="spec")

class DynamicTestSession(Base):
    __tablename__ = "dynamic_test_session"

    id = Column(CHAR(36), primary_key=True, default=generate_uuid)
    spec_id = Column(CHAR(36), ForeignKey("static_spec.id"), nullable=False) # FK to Static Spec
    spec = relationship("StaticSpec", back_populates="sessions")
    target_base_url = Column(String(255), nullable=False)
    auth_token = Column(Text, nullable=True) # JWT / Bearer Token
    auth_token_secondary = Column(Text, nullable=True) # Victim Token for BOLA
    status = Column(SqlEnum(SessionStatus), default=SessionStatus.PENDING)
    
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    initiated_by = Column(String(100), default="admin")

    # Relationships
    test_cases = relationship("DynamicTestCase", back_populates="session", cascade="all, delete-orphan")
    findings = relationship("DynamicFinding", back_populates="session", cascade="all, delete-orphan")

class DynamicTestCase(Base):
    __tablename__ = "dynamic_test_case"

    id = Column(CHAR(36), primary_key=True, default=generate_uuid)
    session_id = Column(CHAR(36), ForeignKey("dynamic_test_session.id"), nullable=False)
    
    endpoint_path = Column(String(255), nullable=False)
    method = Column(String(10), nullable=False)
    check_type = Column(SqlEnum(CheckType), nullable=False)
    
    # Enhanced Fields for Phase 6b
    logs = Column(Text, nullable=True) # Execution Trace
    rule_id = Column(String(255), nullable=True) # Reference to Static Rule ID
    
    status = Column(SqlEnum(CaseStatus), default=CaseStatus.QUEUED)

    session = relationship("DynamicTestSession", back_populates="test_cases")

class DynamicFinding(Base):
    __tablename__ = "dynamic_finding"

    id = Column(CHAR(36), primary_key=True, default=generate_uuid)
    session_id = Column(CHAR(36), ForeignKey("dynamic_test_session.id"), nullable=False)
    test_case_id = Column(CHAR(36), ForeignKey("dynamic_test_case.id"), nullable=True) # Link to Source Case
    
    endpoint_path = Column(String(255), nullable=False)
    method = Column(String(10), nullable=False)
    check_type = Column(SqlEnum(CheckType), nullable=False)
    
    severity = Column(SqlEnum(Severity), nullable=False)
    cvss_score = Column(Float, default=0.0)
    
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)

    session = relationship("DynamicTestSession", back_populates="findings")
    evidence = relationship("DynamicEvidence", back_populates="finding", uselist=False, cascade="all, delete-orphan")

class DynamicEvidence(Base):
    __tablename__ = "dynamic_evidence"

    id = Column(CHAR(36), primary_key=True, default=generate_uuid)
    finding_id = Column(CHAR(36), ForeignKey("dynamic_finding.id"), nullable=False, unique=True)
    
    request_dump = Column(Text, nullable=True) # JSON or Raw Text (Can be large)
    response_dump = Column(Text, nullable=True) # JSON or Raw Text (Can be large)
    created_at = Column(DateTime, default=datetime.utcnow)

    finding = relationship("DynamicFinding", back_populates="evidence")
