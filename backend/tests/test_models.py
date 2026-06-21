import uuid
from datetime import datetime, timedelta
from backend.models import (
    Organization, User, Team, Project,
    ScanTarget, ScanJob, Finding, ApiKey, AuditLog
)

def test_db_models_and_cascade(db_session):
    # 1. Create Organization
    org = Organization(name="Target Org")
    db_session.add(org)
    db_session.commit()
    assert isinstance(org.id, uuid.UUID)

    # 2. Create User
    user = User(
        email="analyst@targetorg.com",
        firebase_uid="uid_analyst",
        role="analyst",
        organization_id=org.id
    )
    db_session.add(user)
    
    # 3. Create Team
    team = Team(name="AppSec", organization_id=org.id)
    db_session.add(team)
    
    # 4. Create Project
    proj = Project(name="Project Ares", organization_id=org.id)
    db_session.add(proj)
    db_session.commit()

    # 5. Create Target
    target = ScanTarget(url="https://secure.org", project_id=proj.id)
    db_session.add(target)
    
    # 6. Create Scan Job
    job = ScanJob(project_id=proj.id, organization_id=org.id, status="pending")
    db_session.add(job)
    db_session.commit()

    # 7. Create Finding
    finding = Finding(
        title="SQL Injection",
        severity="high",
        scan_job_id=job.id,
        organization_id=org.id,
        sla_deadline=datetime.utcnow() # Value will be overwritten by before_insert event listener
    )
    db_session.add(finding)
    
    # 8. Create API Key
    api_key = ApiKey(
        key_hash="hashed_api_key",
        prefix="sk_live_",
        expires_at=datetime.utcnow() + timedelta(days=30),
        organization_id=org.id
    )
    db_session.add(api_key)
    
    # 9. Create Audit Log
    audit = AuditLog(
        action="USER_LOGIN",
        user_id=user.id,
        organization_id=org.id
    )
    db_session.add(audit)
    db_session.commit()

    # Verify all 9 tables exist and are populated
    assert db_session.query(Organization).count() == 1
    assert db_session.query(User).count() == 1
    assert db_session.query(Team).count() == 1
    assert db_session.query(Project).count() == 1
    assert db_session.query(ScanTarget).count() == 1
    assert db_session.query(ScanJob).count() == 1
    assert db_session.query(Finding).count() == 1
    assert db_session.query(ApiKey).count() == 1
    assert db_session.query(AuditLog).count() == 1

    # Verify cascade delete works: deleting organization must delete users, teams, projects, scan_jobs, findings, api_keys, audit_logs
    db_session.delete(org)
    db_session.commit()

    assert db_session.query(Organization).count() == 0
    assert db_session.query(User).count() == 0
    assert db_session.query(Team).count() == 0
    assert db_session.query(Project).count() == 0
    assert db_session.query(ScanTarget).count() == 0
    assert db_session.query(ScanJob).count() == 0
    assert db_session.query(Finding).count() == 0
    assert db_session.query(ApiKey).count() == 0
    assert db_session.query(AuditLog).count() == 0

def test_sla_deadline_auto_computation(db_session):
    org = Organization(name="SLA Test Org")
    db_session.add(org)
    db_session.commit()

    proj = Project(name="SLA Proj", organization_id=org.id)
    db_session.add(proj)
    db_session.commit()

    job = ScanJob(project_id=proj.id, organization_id=org.id, status="pending")
    db_session.add(job)
    db_session.commit()

    severities = {
        "critical": 1,
        "high": 7,
        "medium": 30,
        "low": 90
    }

    for sev, days in severities.items():
        finding = Finding(
            title=f"Test {sev}",
            severity=sev,
            scan_job_id=job.id,
            organization_id=org.id,
            sla_deadline=datetime.utcnow()
        )
        db_session.add(finding)
        db_session.commit()

        expected = datetime.utcnow() + timedelta(days=days)
        # Check difference is less than 10 seconds to account for execution time
        diff = abs((finding.sla_deadline - expected).total_seconds())
        assert diff < 10, f"SLA for {sev} was computed incorrectly"
