import os
import time
import logging
import json
import uuid
from datetime import datetime
from celery import Celery
from celery.exceptions import SoftTimeLimitExceeded
import redis

from backend.database import SessionLocal
from backend.models import ScanJob, Finding
from scanner_engine import ScannerEngineV2

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Initialize Celery app
celery_app = Celery("scanner_tasks", broker=REDIS_URL, backend=REDIS_URL)

# Configure soft time limit to 30 minutes (1800s) and hard limit to 31 minutes (1860s)
celery_app.conf.update(
    task_soft_time_limit=1800,
    task_time_limit=1860,
)

@celery_app.task(name="backend.tasks.run_scan_job", bind=True)
def run_scan_job(self, job_id_str: str):
    """
    Background Celery task to run a security scan job.
    Updates the ScanJob status to running, completed, or failed.
    """
    logger.info(f"Starting background scan job task: {job_id_str}")
    job_id = uuid.UUID(job_id_str)
    
    db = SessionLocal()
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if not job:
        logger.error(f"ScanJob {job_id_str} not found in database.")
        db.close()
        return False

    # Update status to running
    job.status = "running"
    db.commit()

    # Setup redis connection to broadcast progress
    r_client = redis.from_url(REDIS_URL, decode_responses=True)
    channel = f"scan_progress:{job_id_str}"
    
    def broadcast_progress(phase: str, percent: int, message: str = ""):
        payload = {
            "type": "progress",
            "job_id": job_id_str,
            "status": "running",
            "phase": phase,
            "percent": percent,
            "message": message
        }
        try:
            r_client.publish(channel, json.dumps(payload))
        except Exception as e:
            logger.debug(f"Redis publish error: {e}")

    broadcast_progress("initializing", 5, "Initializing scanner engine")

    try:
        # Initialize the scanner engine
        # Trigger all modules by default
        engine_v2 = ScannerEngineV2(
            target_url=job.target_url,
            scan_xss=True,
            scan_stored_xss=True,
            scan_sqli=True,
            scan_headers=True,
            scan_redirect=True,
            scan_directories=True,
            scan_idor=True,
            scan_recon=True,
            scan_ip_leakage=True
        )

        def progress_tracker(phase: str, pct: float, msg: str):
            percent = int(pct * 100)
            broadcast_progress(phase, percent, msg)

        # Run scan
        findings = engine_v2.run(progress_callback=progress_tracker)

        # Save findings in database
        for v in findings:
            finding = Finding(
                title=v.get("title", v.get("type", "Vulnerability")),
                severity=v.get("severity", "Medium"),
                scan_job_id=job_id,
                organization_id=job.organization_id,
                sla_deadline=v.get("sla_deadline", datetime.utcnow()) # Computed automatically by event listener or set default
            )
            db.add(finding)

        job.status = "completed"
        job.error_message = None
        db.commit()

        # Send completion message
        r_client.publish(channel, json.dumps({
            "type": "complete",
            "job_id": job_id_str,
            "status": "completed",
            "phase": "finished",
            "percent": 100,
            "message": f"Scan completed successfully with {len(findings)} findings."
        }))
        logger.info(f"ScanJob {job_id_str} successfully completed.")
        return True

    except SoftTimeLimitExceeded:
        logger.error(f"ScanJob {job_id_str} exceeded 30-minute soft time limit.")
        job.status = "failed"
        job.error_message = "Scan exceeded maximum execution time limit (30 minutes)."
        db.commit()
        r_client.publish(channel, json.dumps({
            "type": "failed",
            "job_id": job_id_str,
            "status": "failed",
            "phase": "error",
            "percent": 100,
            "error": job.error_message
        }))
        return False

    except Exception as e:
        logger.error(f"ScanJob {job_id_str} encountered an error: {e}", exc_info=True)
        job.status = "failed"
        job.error_message = str(e)
        db.commit()
        r_client.publish(channel, json.dumps({
            "type": "failed",
            "job_id": job_id_str,
            "status": "failed",
            "phase": "error",
            "percent": 100,
            "error": job.error_message
        }))
        return False

    finally:
        db.close()
