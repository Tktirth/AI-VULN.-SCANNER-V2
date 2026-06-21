import contextvars
import uuid
import logging
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

# Context variable to hold request ID across async tasks
request_id_var = contextvars.ContextVar("request_id", default=None)

class RequestIdFilter(logging.Filter):
    """
    Log filter to inject request_id into all log records dynamically.
    """
    def filter(self, record):
        record.request_id = request_id_var.get()
        return True

class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Middleware that traces requests by injecting and returning X-Request-ID.
    """
    async def dispatch(self, request: Request, call_next):
        req_id = request.headers.get("X-Request-ID")
        if not req_id:
            req_id = str(uuid.uuid4())
            
        token = request_id_var.set(req_id)
        try:
            response: Response = await call_next(request)
            response.headers["X-Request-ID"] = req_id
            return response
        finally:
            request_id_var.reset(token)

async def global_exception_handler(request: Request, exc: Exception):
    """
    Catch-all exception handler returning RFC 7807 formatted JSON responses.
    """
    logging.error("Unhandled exception occurred", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={
            "type": "/errors/internal-server-error",
            "title": "Internal Server Error",
            "status": 500,
            "detail": "An unexpected error occurred. Stack traces are omitted for security.",
            "instance": request.url.path
        },
        media_type="application/problem+json"
    )

async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """
    HTTPException handler returning RFC 7807 formatted JSON responses.
    """
    logging.warning(f"HTTP Exception at {request.url.path}: {exc.detail}")
    headers = getattr(exc, "headers", None) or {}
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "type": f"/errors/http-error-{exc.status_code}",
            "title": "HTTP Error",
            "status": exc.status_code,
            "detail": str(exc.detail),
            "instance": request.url.path
        },
        headers=headers,
        media_type="application/problem+json"
    )
