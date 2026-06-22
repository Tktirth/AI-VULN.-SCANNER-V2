import uuid
from datetime import datetime, timedelta
from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    ForeignKey,
    Enum,
    JSON,
    event,
    text,
    Index
)
from sqlalchemy.dialects.postgresql import UUID
from backend.database import Base

# Server-side generated UUID generator
UUID_DEFAULT = text("gen_random_uuid()")

class Organization(Base):
    __tablename__ = "organizations"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=UUID_DEFAULT)
    name = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=UUID_DEFAULT)
    email = Column(String, unique=True, nullable=False)
    firebase_uid = Column(String, unique=True, nullable=False)
    role = Column(
        String,
        nullable=False,
        default="viewer" # super_admin, org_admin, security_engineer, analyst, viewer
    )
    is_active = Column(Boolean, default=True, nullable=False)
    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True
    )
    
Index("ix_users_firebase_uid", User.firebase_uid)

class Team(Base):
    __tablename__ = "teams"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=UUID_DEFAULT)
    name = Column(String, nullable=False)
    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False
    )

class Project(Base):
    __tablename__ = "projects"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=UUID_DEFAULT)
    name = Column(String, nullable=False)
    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False
    )

class ScanTarget(Base):
    __tablename__ = "scan_targets"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=UUID_DEFAULT)
    url = Column(String, nullable=False)
    project_id = Column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False
    )

class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=UUID_DEFAULT)
    status = Column(String, nullable=False, default="pending")
    target_url = Column(String, nullable=True)
    error_message = Column(String, nullable=True)
    project_id = Column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False
    )
    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False
    )

class Finding(Base):
    __tablename__ = "findings"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=UUID_DEFAULT)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False) # critical, high, medium, low
    sla_deadline = Column(DateTime, nullable=False)
    scan_job_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False
    )
    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    status = Column(String, default="open", nullable=False) # open, confirmed, in_remediation, resolved, false_positive
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    jira_issue_key = Column(String, nullable=True)

Index("ix_findings_scan_job_id", Finding.scan_job_id)
Index("ix_findings_org_id_created_at", Finding.organization_id, Finding.created_at)

class ApiKey(Base):
    __tablename__ = "api_keys"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=UUID_DEFAULT)
    key_hash = Column(String, unique=True, nullable=False, index=True)
    prefix = Column(String(8), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False)
    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False
    )

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=UUID_DEFAULT)
    action = Column(String, nullable=False) # SSRF_ATTEMPT_BLOCKED, etc.
    details = Column(JSON, nullable=True)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False
    )

# Automatically compute sla_deadline on insert based on severity
@event.listens_for(Finding, "before_insert")
def receive_before_insert(mapper, connection, target):
    now = datetime.utcnow()
    sev = (target.severity or "low").lower()
    if sev == "critical":
        target.sla_deadline = now + timedelta(days=1)
    elif sev == "high":
        target.sla_deadline = now + timedelta(days=7)
    elif sev == "medium":
        target.sla_deadline = now + timedelta(days=30)
    else: # low
        target.sla_deadline = now + timedelta(days=90)
