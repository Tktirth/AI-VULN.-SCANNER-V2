import logging
import json
import sys
import re
from datetime import datetime

# Regex pattern for common secrets
SECRET_PATTERN = re.compile(
    r'(password|token|api_key|cookie|secret)[\s\'"]*[:=][\s\'"]*([^\s\'",}]+)',
    re.IGNORECASE
)

class JsonFormatter(logging.Formatter):
    def format(self, record):
        msg = record.getMessage()
        # Redact secrets
        if isinstance(msg, str):
            msg = SECRET_PATTERN.sub(r'\1: "***"', msg)
            
        log_record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "message": msg,
            "logger": record.name
        }
        # Injects request_id from log record if available
        if hasattr(record, "request_id"):
            log_record["request_id"] = record.request_id
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_record)

def setup_logging():
    from backend.middleware import RequestIdFilter
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # Clears any default handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RequestIdFilter())
    logger.addHandler(handler)
    
    # Intercept Uvicorn loggers
    for logger_name in ("uvicorn", "uvicorn.access", "uvicorn.error", "fastapi"):
        l = logging.getLogger(logger_name)
        l.handlers = [handler]
        l.propagate = False
        
    # Intercept Celery loggers
    for logger_name in ("celery", "celery.task", "celery.worker"):
        l = logging.getLogger(logger_name)
        l.handlers = [handler]
        l.propagate = False
