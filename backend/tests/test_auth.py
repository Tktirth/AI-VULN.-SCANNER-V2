import hashlib
from datetime import datetime, timedelta
from unittest.mock import patch
from fastapi.testclient import TestClient

from backend.auth import enable_firebase_mock, disable_firebase_mock
from backend.models import Organization, User, ApiKey

def test_firebase_authentication_and_caching(client, db_session):
    # Setup test Org and User
    org = Organization(name="Auth Corp")
    db_session.add(org)
    db_session.commit()

    user = User(
        email="user@authcorp.com",
        firebase_uid="firebase_uid_test",
        role="viewer",
        is_active=True,
        organization_id=org.id
    )
    db_session.add(user)
    db_session.commit()

    token_data = {"uid": "firebase_uid_test", "email": "user@authcorp.com"}
    enable_firebase_mock(token_data)

    # Mock the verification function to track calls
    with patch("backend.auth.verify_firebase_token", side_effect=lambda t: token_data) as mock_verify:
        # First Request: hits verify_firebase_token and caches profile
        resp1 = client.get("/auth/profile", headers={"Authorization": "Bearer valid_token"})
        assert resp1.status_code == 200
        assert resp1.json()["email"] == "user@authcorp.com"
        assert mock_verify.call_count == 1

        # Second Request: hits Redis cache directly
        resp2 = client.get("/auth/profile", headers={"Authorization": "Bearer valid_token"})
        assert resp2.status_code == 200
        assert resp2.json()["email"] == "user@authcorp.com"
        # verify_firebase_token is NOT called a second time
        assert mock_verify.call_count == 1

    disable_firebase_mock()

def test_firebase_auth_edge_cases(client, db_session):
    org = Organization(name="Edge Corp")
    db_session.add(org)
    db_session.commit()

    # 1. Account Suspended
    suspended_user = User(
        email="suspended@edge.com",
        firebase_uid="uid_suspended",
        role="viewer",
        is_active=False,
        organization_id=org.id
    )
    db_session.add(suspended_user)
    db_session.commit()

    enable_firebase_mock({"uid": "uid_suspended", "email": "suspended@edge.com"})
    resp = client.get("/auth/profile", headers={"Authorization": "Bearer suspended_token"})
    assert resp.status_code == 403
    assert "Account suspended" in resp.json()["detail"]

    # 2. Account Not Provisioned
    enable_firebase_mock({"uid": "uid_non_existent", "email": "unprovisioned@edge.com"})
    resp = client.get("/auth/profile", headers={"Authorization": "Bearer unprovisioned_token"})
    assert resp.status_code == 403
    assert "Account not provisioned" in resp.json()["detail"]

    # 3. Invalid Token
    disable_firebase_mock()
    resp = client.get("/auth/profile", headers={"Authorization": "Bearer invalid_token"})
    assert resp.status_code == 401

def test_api_key_visibility_and_revocation(client, db_session):
    org = Organization(name="Key Corp")
    db_session.add(org)
    db_session.commit()

    # Mock bearer auth to skip permissions issues
    enable_firebase_mock({"uid": "some_uid", "email": "admin@keycorp.com"})
    user = User(
        email="admin@keycorp.com",
        firebase_uid="some_uid",
        role="super_admin",
        is_active=True,
        organization_id=org.id
    )
    db_session.add(user)
    db_session.commit()

    headers = {"Authorization": "Bearer admin_token"}

    # 1. Create API Key
    resp = client.post("/api-keys", json={"organization_id": str(org.id)}, headers=headers)
    assert resp.status_code == 201
    res_data = resp.json()
    plaintext = res_data["plaintext_key"]
    assert plaintext.startswith("sk_live_")
    
    # 2. List API Keys (shows only prefix)
    resp = client.get("/api-keys", headers=headers)
    assert resp.status_code == 200
    keys_list = resp.json()
    assert len(keys_list) == 1
    assert keys_list[0]["prefix"] == plaintext[:8]
    assert "plaintext_key" not in keys_list[0]
    assert "key_hash" not in keys_list[0]

    # 3. Use API Key to access profile
    profile_resp = client.get("/auth/profile", headers={"X-API-Key": plaintext})
    assert profile_resp.status_code == 200
    assert profile_resp.json()["role"] == "org_admin" # API key operates as org_admin

    # 4. Revoke key
    db_key = db_session.query(ApiKey).filter(ApiKey.prefix == plaintext[:8]).first()
    db_key.is_revoked = True
    db_session.commit()

    # Access is now blocked (returns 401)
    profile_resp = client.get("/auth/profile", headers={"X-API-Key": plaintext})
    assert profile_resp.status_code == 401

def test_api_key_rate_limiting(client, db_session):
    org = Organization(name="Rate Limit Corp")
    db_session.add(org)
    db_session.commit()

    api_key = ApiKey(
        key_hash=hashlib.sha256("test_key".encode()).hexdigest(),
        prefix="sk_live_",
        expires_at=datetime.utcnow() + timedelta(days=30),
        organization_id=org.id
    )
    db_session.add(api_key)
    db_session.commit()

    # Fire 100 requests (all should pass)
    for _ in range(100):
        resp = client.get("/auth/profile", headers={"X-API-Key": "test_key"})
        assert resp.status_code == 200

    # 101st request returns 429
    resp = client.get("/auth/profile", headers={"X-API-Key": "test_key"})
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers
