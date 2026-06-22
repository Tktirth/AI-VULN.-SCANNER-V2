import hashlib
import json
import logging
from datetime import datetime
from typing import Optional, Set
import firebase_admin
from firebase_admin import auth as firebase_auth
from fastapi import Request, Depends, HTTPException, Security
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from backend.database import get_db
from backend import database
from backend.models import User, ApiKey

logger = logging.getLogger(__name__)

# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Initialize Firebase Admin SDK (safely)
try:
    firebase_admin.get_app()
except ValueError:
    firebase_admin.initialize_app()

# RBAC Permissions Definitions
PERMISSIONS = {
    "org:read", "org:write", "org:manage",
    "user:read", "user:write",
    "project:read", "project:write",
    "target:read", "target:write",
    "scan:read", "scan:write",
    "finding:read", "finding:write",
    "audit:read"
}

ROLE_PERMISSIONS = {
    "super_admin": PERMISSIONS.copy(),
    "org_admin": {
        "org:read", "user:read", "user:write",
        "project:read", "project:write", "target:read", "target:write",
        "scan:read", "scan:write", "finding:read", "finding:write", "audit:read"
    },
    "security_engineer": {
        "user:read", "project:read", "project:write", "target:read", "target:write",
        "scan:read", "scan:write", "finding:read", "finding:write"
    },
    "analyst": {
        "project:read", "target:read", "scan:read", "finding:read", "finding:write"
    },
    "viewer": {
        "project:read", "target:read", "scan:read", "finding:read"
    }
}

# In-memory mock controls for pytest testing (without live Firebase)
_firebase_mock_enabled = False
_firebase_mock_user_info = {}

def enable_firebase_mock(user_info: dict):
    global _firebase_mock_enabled, _firebase_mock_user_info
    _firebase_mock_enabled = True
    _firebase_mock_user_info = user_info

def disable_firebase_mock():
    global _firebase_mock_enabled
    _firebase_mock_enabled = False

def verify_firebase_token(token: str) -> dict:
    """
    Verify Firebase JWT ID token. Calls Firebase Admin SDK or uses testing mock.
    """
    dev_token_val = os.getenv("DEV_TOKEN", "dev_token")
    if token == dev_token_val and os.getenv("ENVIRONMENT", "dev") != "prod":
        import os
        return {"uid": "seed_admin_uid", "email": "admin@seedcorp.com"}
        
    if _firebase_mock_enabled:
        invalid_token_val = os.getenv("INVALID_TOKEN", "invalid_token")
        expired_token_val = os.getenv("EXPIRED_TOKEN", "expired_token")
        if token == invalid_token_val or token == expired_token_val:
            raise ValueError("Firebase token is invalid or expired")
        return _firebase_mock_user_info
        
    try:
        return firebase_auth.verify_id_token(token)
    except Exception as e:
        raise ValueError(f"Firebase token verification failed: {str(e)}")

def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    api_key: Optional[str] = Depends(api_key_header),
    db: Session = Depends(get_db)
) -> dict:
    """
    Dependency that authenticates the user either via Firebase JWT or X-API-Key.
    Caches Firebase verification results in Redis.
    """
    # 1. API Key Authentication Path
    if api_key:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Enforce rate limit (100 requests per 60 seconds)
        rl_key = f"rate_limit:apikey:{key_hash}"
        current_requests = database.redis_client.get(rl_key)
        if current_requests and int(current_requests) >= 100:
            ttl = database.redis_client.ttl(rl_key)
            # Ensure TTL is at least 1s
            retry_after = str(max(1, ttl))
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded. Maximum 100 requests per 60 seconds.",
                headers={"Retry-After": retry_after}
            )
        else:
            pipe = database.redis_client.pipeline()
            pipe.incr(rl_key)
            if not current_requests:
                pipe.expire(rl_key, 60)
            pipe.execute()

        db_key = db.query(ApiKey).filter(ApiKey.key_hash == key_hash).first()
        if not db_key or db_key.is_revoked or db_key.expires_at < datetime.utcnow():
            raise HTTPException(status_code=401, detail="Invalid or expired API Key")
            
        # Return a simulated user session context based on organization owner role
        return {
            "id": None,
            "email": f"api_key_{db_key.prefix}@org.internal",
            "role": "org_admin",  # API Key acts with Org Admin privileges
            "organization_id": str(db_key.organization_id),
            "is_active": True,
            "auth_method": "api_key"
        }

    # 2. Firebase JWT Authentication Path
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication credentials missing")
        
    token = credentials.credentials
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    cache_key = f"firebase:token:{token_hash}"
    
    # Check Redis cache
    cached_profile = database.redis_client.get(cache_key)
    if cached_profile:
        return json.loads(cached_profile)
        
    try:
        decoded_token = verify_firebase_token(token)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
        
    firebase_uid = decoded_token.get("uid")
    email = decoded_token.get("email")
    
    user = db.query(User).filter(User.firebase_uid == firebase_uid).first()
    if not user:
        raise HTTPException(status_code=403, detail="Account not provisioned")
        
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account suspended")
        
    profile = {
        "id": str(user.id),
        "email": user.email,
        "role": user.role,
        "organization_id": str(user.organization_id) if user.organization_id else None,
        "is_active": user.is_active,
        "auth_method": "firebase"
    }
    
    # Cache profile in Redis for 1 hour
    database.redis_client.setex(cache_key, 3600, json.dumps(profile))
    return profile

class PermissionChecker:
    def __init__(self, permission: str):
        self.permission = permission

    def __call__(self, current_user: dict = Depends(get_current_user)) -> dict:
        role = current_user.get("role")
        allowed_perms = ROLE_PERMISSIONS.get(role, set())
        if self.permission not in allowed_perms:
            raise HTTPException(status_code=403, detail="Forbidden: Insufficient permissions")
        return current_user

def require_permission(permission: str):
    return Security(PermissionChecker(permission))
