import secrets
import hashlib
import uuid
import os
import asyncio
import json
from google.cloud import storage
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field, field_serializer
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.database import get_db
from backend.models import (
    Organization, User, Team, Project,
    ScanTarget, ScanJob, Finding, ApiKey, AuditLog
)
from backend.auth import require_permission, get_current_user
from backend.ssrf import validate_scan_target

# Define routers
auth_router = APIRouter(prefix="/auth", tags=["auth"])
org_router = APIRouter(prefix="/organizations", tags=["organizations"])
team_router = APIRouter(prefix="/teams", tags=["teams"])
ws_router = APIRouter(prefix="/ws", tags=["websockets"])
project_router = APIRouter(prefix="/projects", tags=["projects"])
target_router = APIRouter(prefix="/scan-targets", tags=["scan-targets"])
job_router = APIRouter(prefix="/scan-jobs", tags=["scan-jobs"])
finding_router = APIRouter(prefix="/findings", tags=["findings"])
api_key_router = APIRouter(prefix="/api-keys", tags=["api-keys"])

# --- Pydantic Schemas ---
class UserProfileResponse(BaseModel):
    id: Optional[str]
    email: str
    role: str
    organization_id: Optional[str]
    is_active: bool

class OrgCreate(BaseModel):
    name: str

class OrgResponse(BaseModel):
    id: uuid.UUID
    name: str
    created_at: datetime
    
    @field_serializer('created_at')
    def serialize_dt(self, dt: datetime, _info):
        return dt.isoformat() + "Z" if dt else None

    class Config:
        from_attributes = True

class TeamCreate(BaseModel):
    name: str
    organization_id: str

class TeamResponse(BaseModel):
    id: uuid.UUID
    name: str
    organization_id: uuid.UUID
    class Config:
        from_attributes = True

class ProjectCreate(BaseModel):
    name: str
    organization_id: str

class ProjectResponse(BaseModel):
    id: uuid.UUID
    name: str
    organization_id: uuid.UUID
    class Config:
        from_attributes = True

class TargetCreate(BaseModel):
    url: str
    project_id: str

class TargetResponse(BaseModel):
    id: uuid.UUID
    url: str
    project_id: uuid.UUID
    class Config:
        from_attributes = True

class JobCreate(BaseModel):
    project_id: str
    target_url: str
    authorization_confirmed: bool

class JobResponse(BaseModel):
    id: uuid.UUID
    status: str
    project_id: uuid.UUID
    organization_id: uuid.UUID
    class Config:
        from_attributes = True

class FindingCreate(BaseModel):
    title: str
    severity: str
    scan_job_id: str

class FindingUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    jira_issue_key: Optional[str] = None

class FindingResponse(BaseModel):
    id: uuid.UUID
    title: str
    severity: str
    status: str
    assigned_to: Optional[uuid.UUID] = None
    jira_issue_key: Optional[str] = None
    sla_deadline: datetime
    scan_job_id: uuid.UUID
    organization_id: uuid.UUID
    
    @field_serializer('sla_deadline')
    def serialize_dt(self, dt: datetime, _info):
        return dt.isoformat() + "Z" if dt else None

    class Config:
        from_attributes = True

class FindingPageResponse(BaseModel):
    items: List[FindingResponse]
    next_cursor: Optional[str]

class ApiKeyCreate(BaseModel):
    organization_id: str

class ApiKeyCreateResponse(BaseModel):
    id: uuid.UUID
    prefix: str
    plaintext_key: str
    expires_at: datetime
    
    @field_serializer('expires_at')
    def serialize_dt(self, dt: datetime, _info):
        return dt.isoformat() + "Z" if dt else None

class ApiKeyResponse(BaseModel):
    id: uuid.UUID
    prefix: str
    expires_at: datetime
    is_revoked: bool
    
    @field_serializer('expires_at')
    def serialize_dt(self, dt: datetime, _info):
        return dt.isoformat() + "Z" if dt else None

    class Config:
        from_attributes = True

# --- 1. Auth Router ---
@auth_router.get("/profile", response_model=UserProfileResponse)
def get_profile(current_user: dict = Depends(get_current_user)):
    return current_user

# --- 2. Organizations Router ---
@org_router.post("", response_model=OrgResponse, status_code=status.HTTP_201_CREATED)
def create_org(org: OrgCreate, db: Session = Depends(get_db), current_user: dict = require_permission("org:write")):
    db_org = Organization(name=org.name)
    db.add(db_org)
    try:
        db.commit()
        db.refresh(db_org)
    except Exception:
        db.rollback()
        raise HTTPException(status_code=400, detail="Organization already exists")
    return db_org

@org_router.get("", response_model=List[OrgResponse])
def list_orgs(db: Session = Depends(get_db), current_user: dict = require_permission("org:read")):
    # Tenant separation: Org Admin can only access their own org
    if current_user["role"] != "super_admin":
        return db.query(Organization).filter(Organization.id == uuid.UUID(current_user["organization_id"])).all()
    return db.query(Organization).all()

@org_router.get("/{org_id}/manage")
def manage_org(org_id: str, current_user: dict = require_permission("org:manage")):
    # Verify tenant access
    if current_user["role"] != "super_admin" and current_user["organization_id"] != org_id:
        raise HTTPException(status_code=403, detail="Forbidden: Cannot access another organization's data")
    return {"status": "success", "managed_organization": org_id}

# --- 3. Teams Router ---
@team_router.post("", response_model=TeamResponse, status_code=status.HTTP_201_CREATED)
def create_team(team: TeamCreate, db: Session = Depends(get_db), current_user: dict = require_permission("org:write")):
    if current_user["role"] != "super_admin" and current_user["organization_id"] != team.organization_id:
        raise HTTPException(status_code=403, detail="Forbidden: Cannot access another organization's data")
    db_team = Team(name=team.name, organization_id=uuid.UUID(team.organization_id))
    db.add(db_team)
    db.commit()
    db.refresh(db_team)
    return db_team

@team_router.get("", response_model=List[TeamResponse])
def list_teams(db: Session = Depends(get_db), current_user: dict = require_permission("user:read")):
    if current_user["role"] != "super_admin":
        return db.query(Team).filter(Team.organization_id == uuid.UUID(current_user["organization_id"])).all()
    return db.query(Team).all()

# --- 4. Projects Router ---
@project_router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(project: ProjectCreate, db: Session = Depends(get_db), current_user: dict = require_permission("project:write")):
    if current_user["role"] != "super_admin" and current_user["organization_id"] != project.organization_id:
        raise HTTPException(status_code=403, detail="Forbidden: Cannot access another organization's data")
    db_proj = Project(name=project.name, organization_id=uuid.UUID(project.organization_id))
    db.add(db_proj)
    db.commit()
    db.refresh(db_proj)
    return db_proj

@project_router.get("", response_model=List[ProjectResponse])
def list_projects(db: Session = Depends(get_db), current_user: dict = require_permission("project:read")):
    if current_user["role"] != "super_admin":
        return db.query(Project).filter(Project.organization_id == current_user["organization_id"]).all()
    return db.query(Project).all()

# --- 5. Scan Targets Router ---
@target_router.post("", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def create_target(target: TargetCreate, db: Session = Depends(get_db), current_user: dict = require_permission("target:write")):
    # Verify target project belongs to user's org
    project = db.query(Project).filter(Project.id == target.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if current_user["role"] != "super_admin" and current_user["organization_id"] != str(project.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cannot access another organization's data")
        
    db_target = ScanTarget(url=target.url, project_id=uuid.UUID(target.project_id))
    db.add(db_target)
    db.commit()
    db.refresh(db_target)
    return db_target

@target_router.get("", response_model=List[TargetResponse])
def list_targets(db: Session = Depends(get_db), current_user: dict = require_permission("target:read")):
    if current_user["role"] != "super_admin":
        return db.query(ScanTarget).join(Project).filter(Project.organization_id == uuid.UUID(current_user["organization_id"])).all()
    return db.query(ScanTarget).all()

# --- 6. Scan Jobs Router ---
@job_router.post("", response_model=JobResponse, status_code=status.HTTP_201_CREATED)
def create_job(job: JobCreate, db: Session = Depends(get_db), current_user: dict = require_permission("scan:write")):
    project = db.query(Project).filter(Project.id == uuid.UUID(job.project_id)).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if current_user["role"] != "super_admin" and current_user["organization_id"] != str(project.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cannot access another organization's data")
        
    # Enforces SSRF and authorization checks (raises 400 if blocked or unconfirmed)
    validate_scan_target(
        url=job.target_url,
        authorization_confirmed=job.authorization_confirmed,
        user_id=current_user["id"],
        organization_id=str(project.organization_id),
        db=db
    )
    
    db_job = ScanJob(
        project_id=uuid.UUID(job.project_id),
        organization_id=project.organization_id,
        status="pending",
        target_url=job.target_url
    )
    db.add(db_job)
    db.commit()
    db.refresh(db_job)

    # Trigger Celery background task
    from backend.tasks import run_scan_job
    run_scan_job.delay(str(db_job.id))

    return db_job

@job_router.get("", response_model=List[JobResponse])
def list_jobs(db: Session = Depends(get_db), current_user: dict = require_permission("scan:read")):
    if current_user["role"] != "super_admin":
        return db.query(ScanJob).filter(ScanJob.organization_id == uuid.UUID(current_user["organization_id"])).all()
    return db.query(ScanJob).all()

@job_router.get("/{job_id}/report")
def get_job_report_url(job_id: str, db: Session = Depends(get_db), current_user: dict = require_permission("scan:read")):
    job = db.query(ScanJob).filter(ScanJob.id == uuid.UUID(job_id)).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if current_user["role"] != "super_admin" and str(job.organization_id) != current_user["organization_id"]:
        raise HTTPException(status_code=403, detail="Forbidden: Cannot access another organization's data")

    bucket_name = os.getenv("GCS_BUCKET_NAME", "web-vulnarebility-scanner-reports")
    blob_name = f"reports/{job_id}.json"
    
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        url = blob.generate_signed_url(
            version="v4",
            expiration=timedelta(minutes=15),
            method="GET",
        )
        return {"report_url": url}
    except Exception:
        # Fallback for dev/local or testing environments
        mock_url = f"https://storage.googleapis.com/{bucket_name}/{blob_name}?mock_signature=true&expires={int((datetime.utcnow() + timedelta(minutes=15)).timestamp())}"
        return {"report_url": mock_url}


@job_router.delete("/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan_job(job_id: str, db: Session = Depends(get_db), current_user: dict = require_permission("scan:write")):
    job = db.query(ScanJob).filter(ScanJob.id == uuid.UUID(job_id)).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if current_user["role"] != "super_admin" and str(job.organization_id) != current_user["organization_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")

    job.status = "cancelled"
    db.commit()
    
    # Attempt to revoke Celery task
    try:
        from backend.tasks import celery_app
        from celery.app.control import Control
        Control(celery_app).revoke(job_id, terminate=True, signal="SIGTERM")
    except Exception as e:
        import logging
        logging.error(f"Failed to revoke celery task {job_id}: {e}")
        
    return None

# --- 7. Findings Router ---
@finding_router.post("", response_model=FindingResponse, status_code=status.HTTP_201_CREATED)
def create_finding(finding: FindingCreate, db: Session = Depends(get_db), current_user: dict = require_permission("finding:write")):
    job = db.query(ScanJob).filter(ScanJob.id == uuid.UUID(finding.scan_job_id)).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if current_user["role"] != "super_admin" and current_user["organization_id"] != str(job.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cannot access another organization's data")
        
    db_finding = Finding(
        title=finding.title,
        severity=finding.severity,
        scan_job_id=uuid.UUID(finding.scan_job_id),
        organization_id=job.organization_id,
        sla_deadline=datetime.utcnow() # Computed automatically by SqlAlchemy event listener before insert
    )
    db.add(db_finding)
    db.commit()
    db.refresh(db_finding)
    return db_finding

@finding_router.get("", response_model=FindingPageResponse)
def list_findings(
    cursor: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db), 
    current_user: dict = require_permission("finding:read")
):
    import base64
    query = db.query(Finding)
    if current_user["role"] != "super_admin":
        query = query.filter(Finding.organization_id == uuid.UUID(current_user["organization_id"]))
        
    if cursor:
        try:
            decoded = base64.b64decode(cursor).decode('utf-8')
            created_at_str, finding_id_str = decoded.split("|")
            dt = datetime.fromisoformat(created_at_str)
            # Find elements older than cursor
            query = query.filter(
                (Finding.created_at < dt) | 
                ((Finding.created_at == dt) & (Finding.id < uuid.UUID(finding_id_str)))
            )
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid cursor")

    # Order by newest first
    query = query.order_by(Finding.created_at.desc(), Finding.id.desc())
    items = query.limit(limit).all()
    
    next_cursor = None
    if len(items) == limit:
        last = items[-1]
        raw_cursor = f"{last.created_at.isoformat()}|{str(last.id)}"
        next_cursor = base64.b64encode(raw_cursor.encode('utf-8')).decode('utf-8')
        
    return {"items": items, "next_cursor": next_cursor}

@finding_router.patch("/{finding_id}", response_model=FindingResponse)
def update_finding(finding_id: str, update_data: FindingUpdate, db: Session = Depends(get_db), current_user: dict = require_permission("finding:write")):
    finding = db.query(Finding).filter(Finding.id == uuid.UUID(finding_id)).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    if current_user["role"] != "super_admin" and str(finding.organization_id) != current_user["organization_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")

    if update_data.status is not None:
        finding.status = update_data.status
    if update_data.assigned_to is not None:
        finding.assigned_to = uuid.UUID(update_data.assigned_to) if update_data.assigned_to else None
    if update_data.jira_issue_key is not None:
        finding.jira_issue_key = update_data.jira_issue_key

    db.commit()
    db.refresh(finding)
    return finding

# --- 8. API Keys Router ---
@api_key_router.post("", response_model=ApiKeyCreateResponse, status_code=status.HTTP_201_CREATED)
def create_api_key(key_in: ApiKeyCreate, db: Session = Depends(get_db), current_user: dict = require_permission("org:write")):
    if current_user["role"] != "super_admin" and current_user["organization_id"] != key_in.organization_id:
        raise HTTPException(status_code=403, detail="Forbidden: Cannot access another organization's data")
        
    plaintext = "sk_live_" + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    prefix = plaintext[:8]
    expires = datetime.utcnow() + timedelta(days=365)
    
    db_key = ApiKey(
        key_hash=key_hash,
        prefix=prefix,
        expires_at=expires,
        organization_id=uuid.UUID(key_in.organization_id)
    )
    db.add(db_key)
    db.commit()
    db.refresh(db_key)
    
    return ApiKeyCreateResponse(
        id=str(db_key.id),
        prefix=prefix,
        plaintext_key=plaintext,
        expires_at=expires
    )

@api_key_router.get("", response_model=List[ApiKeyResponse])
def list_api_keys(db: Session = Depends(get_db), current_user: dict = require_permission("org:read")):
    # Returns only key prefixes, never the full hash or plaintext keys
    if current_user["role"] != "super_admin":
        return db.query(ApiKey).filter(ApiKey.organization_id == uuid.UUID(current_user["organization_id"])).all()
    return db.query(ApiKey).all()


# --- 9. WebSockets Router ---
@ws_router.websocket("/scan/{job_id}")
async def scan_job_websocket(websocket: WebSocket, job_id: str):
    await websocket.accept()
    
    import redis
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    r_client = redis.from_url(redis_url, decode_responses=True)
    pubsub = r_client.pubsub()
    channel = f"scan_progress:{job_id}"
    pubsub.subscribe(channel)
    
    logger.info(f"WebSocket client connected to scan job channel: {channel}")
    
    try:
        while True:
            # Check for Redis messages
            message = pubsub.get_message(ignore_subscribe_messages=True)
            if message:
                data = message["data"]
                await websocket.send_text(data)
                
                # Check for completion
                try:
                    parsed = json.loads(data)
                    if parsed.get("type") in ("complete", "failed"):
                        break
                except Exception:
                    pass
            
            await asyncio.sleep(0.1)
            
            # Non-blocking check for client disconnect
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=0.01)
            except asyncio.TimeoutError:
                pass
            except WebSocketDisconnect:
                logger.info(f"WebSocket client disconnected from {channel}")
                break
    except Exception as e:
        logger.error(f"WebSocket error on channel {channel}: {e}")
    finally:
        pubsub.unsubscribe(channel)
        pubsub.close()
        try:
            await websocket.close()
        except Exception:
            pass
