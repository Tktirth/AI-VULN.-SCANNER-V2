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

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware that enforces a rate limit using Redis.
    Injects X-RateLimit-* headers into responses.
    """
    async def dispatch(self, request: Request, call_next):
        # We only rate-limit API routes, ignore health check and docs
        if request.url.path.startswith(("/health", "/docs", "/openapi.json")):
            return await call_next(request)

        import time
        from backend.database import redis_client
        
        # Simple IP-based rate limit if no user is found yet
        # A more robust system would use the user ID from the token
        client_ip = request.client.host if request.client else "127.0.0.1"
        key = f"rate_limit:{client_ip}"
        limit = 100
        window = 60
        
        try:
            current = redis_client.get(key)
            if current and int(current) >= limit:
                # Get TTL for Reset header
                ttl = redis_client.ttl(key)
                if ttl < 0:
                    ttl = window
                
                reset_time = int(time.time() + ttl)
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too Many Requests"},
                    headers={
                        "X-RateLimit-Limit": str(limit),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(reset_time),
                        "Retry-After": str(ttl)
                    }
                )
            
            # Increment and set expire if it's the first request
            pipe = redis_client.pipeline()
            pipe.incr(key)
            # Only set expire if key is new (current is None)
            if not current:
                pipe.expire(key, window)
            res = pipe.execute()
            
            # For pipeline: [incr_result, expire_result(if present)]
            requests_made = int(res[0])
            ttl = redis_client.ttl(key)
            if ttl < 0:
                ttl = window
                
            response: Response = await call_next(request)
            
            # Inject RateLimit headers
            response.headers["X-RateLimit-Limit"] = str(limit)
            response.headers["X-RateLimit-Remaining"] = str(max(0, limit - requests_made))
            response.headers["X-RateLimit-Reset"] = str(int(time.time() + ttl))
            
            return response
            
        except Exception as e:
            # If Redis fails, log and bypass rate limiting
            logging.error(f"Rate limiting failed: {e}")
            return await call_next(request)

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
