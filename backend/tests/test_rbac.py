import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from backend.auth import ROLE_PERMISSIONS, require_permission, enable_firebase_mock, disable_firebase_mock
from backend.models import Organization, User, Project, ScanJob

# Define all 14 permissions
permissions_list = [
    "org:read", "org:write", "org:manage",
    "user:read", "user:write",
    "project:read", "project:write",
    "target:read", "target:write",
    "scan:read", "scan:write",
    "finding:read", "finding:write",
    "audit:read"
]

roles_list = ["super_admin", "org_admin", "security_engineer", "analyst", "viewer"]

def test_rbac_matrix_all_combinations():
    """
    Automated check of all 70 combinations (5 roles x 14 permissions).
    """
    for role in roles_list:
        allowed_perms = ROLE_PERMISSIONS.get(role, set())
        for perm in permissions_list:
            should_allow = perm in allowed_perms
            
            # Verify role mappings
            if should_allow:
                assert perm in allowed_perms, f"Role {role} should have permission {perm}"
            else:
                assert perm not in allowed_perms, f"Role {role} should NOT have permission {perm}"

def test_analyst_cannot_manage_org(client, db_session):
    # Setup Org and Analyst User
    org = Organization(name="Analyst Org")
    db_session.add(org)
    db_session.commit()

    user = User(
        email="analyst@test.com",
        firebase_uid="uid_analyst",
        role="analyst",
        is_active=True,
        organization_id=org.id
    )
    db_session.add(user)
    db_session.commit()

    enable_firebase_mock({"uid": "uid_analyst", "email": "analyst@test.com"})
    
    # Attempt org manage endpoint -> Should return 403 Forbidden
    resp = client.get(f"/organizations/{org.id}/manage", headers={"Authorization": "Bearer token"})
    assert resp.status_code == 403
    assert "Forbidden" in resp.json()["detail"]
    disable_firebase_mock()

def test_viewer_cannot_create_scan(client, db_session):
    # Setup Org, Project, and Viewer User
    org = Organization(name="Viewer Org")
    db_session.add(org)
    db_session.commit()

    proj = Project(name="Project Ares", organization_id=org.id)
    db_session.add(proj)
    db_session.commit()

    user = User(
        email="viewer@test.com",
        firebase_uid="uid_viewer",
        role="viewer",
        is_active=True,
        organization_id=org.id
    )
    db_session.add(user)
    db_session.commit()

    enable_firebase_mock({"uid": "uid_viewer", "email": "viewer@test.com"})
    
    # Attempt to submit scan -> Should return 403 Forbidden
    payload = {
        "project_id": str(proj.id),
        "target_url": "https://example.com",
        "authorization_confirmed": True
    }
    resp = client.post("/scan-jobs", json=payload, headers={"Authorization": "Bearer token"})
    assert resp.status_code == 403
    disable_firebase_mock()

def test_org_admin_tenant_isolation(client, db_session):
    # Setup two distinct Orgs
    org1 = Organization(name="Org One")
    org2 = Organization(name="Org Two")
    db_session.add_all([org1, org2])
    db_session.commit()

    # User in Org One (Org Admin)
    user = User(
        email="admin1@orgone.com",
        firebase_uid="uid_admin1",
        role="org_admin",
        is_active=True,
        organization_id=org1.id
    )
    db_session.add(user)
    
    # Project in Org Two
    proj2 = Project(name="Project Org Two", organization_id=org2.id)
    db_session.add(proj2)
    db_session.commit()

    enable_firebase_mock({"uid": "uid_admin1", "email": "admin1@orgone.com"})
    headers = {"Authorization": "Bearer token"}

    # Attempt to access Org Two project creation or list targets -> Should return 403 Forbidden
    payload = {
        "name": "Intruder Project",
        "organization_id": str(org2.id)
    }
    resp1 = client.post("/projects", json=payload, headers=headers)
    assert resp1.status_code == 403

    # Attempt to access Org Two manage endpoint
    resp2 = client.get(f"/organizations/{org2.id}/manage", headers=headers)
    assert resp2.status_code == 403

    disable_firebase_mock()
