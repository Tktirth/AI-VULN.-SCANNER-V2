import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.database import get_db
from backend import database
from backend.logging_config import setup_logging
from backend.middleware import (
    RequestIdMiddleware,
    global_exception_handler,
    http_exception_handler
)
from backend.routers import (
    auth_router, org_router, team_router, project_router,
    target_router, job_router, finding_router, api_key_router,
    ws_router
)
from backend.analytics import analytics_router
from backend.reports_router import reports_router
from backend.integrations.router import integration_router

# Set up structured JSON logging to stdout
setup_logging()

# In production, disable interactive OpenAPI documentation
docs_url = "/docs"
if os.getenv("ENVIRONMENT") == "prod":
    docs_url = None

app = FastAPI(
    title="AI Vulnerability Scanner V2 Backend",
    version="2.0.0",
    docs_url=docs_url,
    redoc_url=None
)

# Add middleware for X-Request-ID tracking
app.add_middleware(RequestIdMiddleware)

# Register custom global exception handlers returning RFC 7807 problem details
app.add_exception_handler(Exception, global_exception_handler)
app.add_exception_handler(StarletteHTTPException, http_exception_handler)

# Include all routers
app.include_router(auth_router)
app.include_router(org_router)
app.include_router(team_router)
app.include_router(project_router)
app.include_router(target_router)
app.include_router(job_router)
app.include_router(finding_router)
app.include_router(api_key_router)
app.include_router(ws_router)
app.include_router(analytics_router)
app.include_router(reports_router)
app.include_router(integration_router)

# Health endpoint checking both PostgreSQL and Redis connectivity
@app.get("/health", status_code=status.HTTP_200_OK)
def health_check(db: Session = Depends(get_db)):
    db_ok = False
    redis_ok = False
    
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        pass
        
    try:
        if database.redis_client.ping():
            redis_ok = True
    except Exception:
        pass
        
    if not db_ok or not redis_ok:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "error",
                "db": "ok" if db_ok else "unreachable",
                "redis": "ok" if redis_ok else "unreachable"
            }
        )
        
    return {
        "status": "ok",
        "db": "ok",
        "redis": "ok"
    }
