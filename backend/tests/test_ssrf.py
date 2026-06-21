import socket
from unittest.mock import patch
from backend.ssrf import is_ssrf_safe
from backend.models import Organization, User, Project, AuditLog
from backend.auth import enable_firebase_mock, disable_firebase_mock

def test_ssrf_guard_logic():
    # 1. Block private/local IPs
    blocked_ips = ["10.0.0.1", "192.168.1.1", "169.254.169.254", "127.0.0.1", "::1"]
    for ip in blocked_ips:
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, None, None, None, (ip, 0))]):
            assert not is_ssrf_safe(f"http://{ip}/")
            assert not is_ssrf_safe(f"http://testdomain.local/")

    # 2. Allow public IPs
    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, None, None, None, ("8.8.8.8", 0))]):
        assert is_ssrf_safe("http://8.8.8.8/")
        assert is_ssrf_safe("http://google.com/")

def test_ssrf_blocking_integration(client, db_session):
    # Setup test org, project, and user (role: org_admin so it can submit scans)
    org = Organization(name="SSRF Corp")
    db_session.add(org)
    db_session.commit()

    project = Project(name="Project Safety", organization_id=org.id)
    db_session.add(project)
    db_session.commit()

    user = User(
        email="engineer@ssrf.com",
        firebase_uid="uid_engineer",
        role="org_admin",
        is_active=True,
        organization_id=org.id
    )
    db_session.add(user)
    db_session.commit()

    enable_firebase_mock({"uid": "uid_engineer", "email": "engineer@ssrf.com"})
    headers = {"Authorization": "Bearer token"}

    # 1. Submit scan with SSRF-unsafe target
    payload = {
        "project_id": str(project.id),
        "target_url": "http://127.0.0.1:8080",
        "authorization_confirmed": True
    }
    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, None, None, None, ("127.0.0.1", 0))]):
        resp = client.post("/scan-jobs", json=payload, headers=headers)
        assert resp.status_code == 400
        assert "SSRF Blocked" in resp.json()["detail"]

    # Verify audit log entry was written
    audit_logs = db_session.query(AuditLog).all()
    assert len(audit_logs) == 1
    assert audit_logs[0].action == "SSRF_ATTEMPT_BLOCKED"
    assert audit_logs[0].organization_id == org.id

    # 2. Submit scan without authorization confirmation
    payload = {
        "project_id": str(project.id),
        "target_url": "http://8.8.8.8",
        "authorization_confirmed": False
    }
    resp = client.post("/scan-jobs", json=payload, headers=headers)
    assert resp.status_code == 400
    assert "authorization_confirmed must be true" in resp.json()["detail"]

    disable_firebase_mock()
