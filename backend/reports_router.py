"""
Reports endpoints for the AI Vulnerability Scanner V2.

Provides PDF generation (async via Celery), PDF download (GCS signed URL),
SARIF 2.1.0 JSON export, and CSV download for a given scan job.  All
endpoints require the ``scan:read`` permission and enforce organisation-level
tenant isolation.
"""

import csv
import io
import json
import logging
import os
import uuid
from datetime import datetime, timedelta
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.auth import require_permission
from backend.database import get_db
from backend.models import ScanJob, Finding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
reports_router = APIRouter(prefix="/reports", tags=["reports"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------
class PDFTaskResponse(BaseModel):
    task_id: str
    status: str


class PDFUrlResponse(BaseModel):
    url: str
    expires_in_seconds: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

GCS_BUCKET_NAME = os.getenv("GCS_BUCKET_NAME", "web-vulnarebility-scanner-reports")


def _get_scan_job_or_404(
    scan_job_id: str,
    db: Session,
    current_user: dict,
) -> ScanJob:
    """
    Fetch a ScanJob by id. Raises 404 if not found and 403 if the caller's
    organisation does not own it.
    """
    try:
        job_uuid = uuid.UUID(scan_job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan_job_id format")

    job = db.query(ScanJob).filter(ScanJob.id == job_uuid).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    if (
        current_user["role"] != "super_admin"
        and str(job.organization_id) != current_user["organization_id"]
    ):
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Cannot access another organization's data",
        )

    return job


def _get_findings_for_job(scan_job_id: uuid.UUID, db: Session) -> List[Finding]:
    """Return all findings associated with a scan job."""
    return db.query(Finding).filter(Finding.scan_job_id == scan_job_id).all()


def _build_sarif(job: ScanJob, findings: List[Finding]) -> dict:
    """
    Build a SARIF 2.1.0 compliant JSON document for the given scan job and
    its findings.

    Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
    """
    severity_to_level = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }

    results = []
    rules = []
    rule_ids_seen: set = set()

    for f in findings:
        rule_id = f.severity.lower()
        if rule_id not in rule_ids_seen:
            rules.append(
                {
                    "id": rule_id,
                    "shortDescription": {"text": f"Severity: {f.severity}"},
                }
            )
            rule_ids_seen.add(rule_id)

        results.append(
            {
                "ruleId": rule_id,
                "level": severity_to_level.get(f.severity.lower(), "note"),
                "message": {"text": f.title},
                "properties": {
                    "id": str(f.id),
                    "sla_deadline": f.sla_deadline.isoformat() if f.sla_deadline else None,
                },
            }
        )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AI Vulnerability Scanner V2",
                        "version": "2.0.0",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "scan_job_id": str(job.id),
                    "target_url": job.target_url,
                    "status": job.status,
                },
            }
        ],
    }

    return sarif


# ---------------------------------------------------------------------------
# Celery task – PDF generation
# ---------------------------------------------------------------------------

def _get_celery_app():
    """Lazy import to avoid circular dependency at module-load time."""
    from backend.tasks import celery_app
    return celery_app


@_get_celery_app().task(name="backend.reports_router.generate_pdf_task", bind=True)
def generate_pdf_task(self, scan_job_id: str):
    """
    Celery task that generates a PDF report for a scan job and uploads it
    to Google Cloud Storage.

    The actual PDF rendering is intentionally kept simple (JSON-based stub)
    so the module works without heavyweight PDF libraries in CI.  Replace
    the ``_render_pdf_bytes`` call with a real renderer (e.g. WeasyPrint,
    ReportLab) when ready.
    """
    from backend.database import SessionLocal
    from google.cloud import storage as gcs_storage

    logger.info("Generating PDF report for scan job %s", scan_job_id)

    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == uuid.UUID(scan_job_id)).first()
        if not job:
            logger.error("ScanJob %s not found – cannot generate PDF.", scan_job_id)
            return False

        findings = _get_findings_for_job(job.id, db)

        from reports.pdf_generator import generate_pdf_report
        
        # Summary statistics
        summary = {
            "total_vulnerabilities": len(findings),
            "pages_scanned": 1, # Default placeholder
            "scan_duration_seconds": 60, # Default placeholder
            "severity_breakdown": {
                "Critical": len([f for f in findings if f.severity.lower() == "critical"]),
                "High": len([f for f in findings if f.severity.lower() == "high"]),
                "Medium": len([f for f in findings if f.severity.lower() == "medium"]),
                "Low": len([f for f in findings if f.severity.lower() == "low"]),
            }
        }
        
        # Format finding dicts
        vuln_dicts = [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity.capitalize(),
                "type": f.title,
                "url": job.target_url,
                "parameter": "",
                "payload": "",
                "evidence": "",
                "remediation": ""
            }
            for f in findings
        ]
        
        pdf_bytes = generate_pdf_report(
            target_url=job.target_url or "Unknown",
            org_name="Organization", # Would come from Organization model
            scan_date=datetime.utcnow().isoformat(),
            vulnerabilities=vuln_dicts,
            summary=summary
        )

        # --- Upload to GCS ---
        blob_path = f"reports/{scan_job_id}.pdf"
        try:
            client = gcs_storage.Client()
            bucket = client.bucket(GCS_BUCKET_NAME)
            blob = bucket.blob(blob_path)
            blob.upload_from_string(pdf_bytes, content_type="application/pdf")
            logger.info("PDF uploaded to gs://%s/%s", GCS_BUCKET_NAME, blob_path)
        except Exception as exc:
            logger.error("GCS upload failed for %s: %s", scan_job_id, exc)
            raise

        return True

    except Exception:
        logger.exception("PDF generation failed for scan job %s", scan_job_id)
        raise
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 1.  POST /reports/{scan_job_id}/pdf  —  trigger async PDF generation
# ---------------------------------------------------------------------------
@reports_router.post(
    "/{scan_job_id}/pdf",
    response_model=PDFTaskResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def trigger_pdf_generation(
    scan_job_id: str,
    db: Session = Depends(get_db),
    current_user: dict = require_permission("scan:read"),
):
    """Enqueue a Celery task to generate a PDF report for the scan job."""
    _get_scan_job_or_404(scan_job_id, db, current_user)

    task = generate_pdf_task.delay(scan_job_id)

    return PDFTaskResponse(task_id=task.id, status="processing")


# ---------------------------------------------------------------------------
# 2.  GET /reports/{scan_job_id}/pdf  —  return signed GCS URL
# ---------------------------------------------------------------------------
@reports_router.get("/{scan_job_id}/pdf", response_model=PDFUrlResponse)
def get_pdf_url(
    scan_job_id: str,
    db: Session = Depends(get_db),
    current_user: dict = require_permission("scan:read"),
):
    """
    Return a time-limited signed URL pointing to the generated PDF in GCS.

    Returns 404 if the PDF has not been generated yet.
    """
    _get_scan_job_or_404(scan_job_id, db, current_user)

    blob_path = f"reports/{scan_job_id}.pdf"
    expiry = timedelta(hours=1)

    try:
        from google.cloud import storage as gcs_storage

        client = gcs_storage.Client()
        bucket = client.bucket(GCS_BUCKET_NAME)
        blob = bucket.blob(blob_path)

        if not blob.exists():
            raise HTTPException(
                status_code=404,
                detail="PDF report has not been generated yet. "
                       "Trigger generation via POST first.",
            )

        signed_url = blob.generate_signed_url(
            version="v4",
            expiration=expiry,
            method="GET",
        )

        return PDFUrlResponse(url=signed_url, expires_in_seconds=int(expiry.total_seconds()))

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to generate signed URL for %s: %s", scan_job_id, exc)
        # Fallback for dev/local environments without GCS credentials
        mock_url = (
            f"https://storage.googleapis.com/{GCS_BUCKET_NAME}/{blob_path}"
            f"?mock_signature=true&expires="
            f"{int((datetime.utcnow() + expiry).timestamp())}"
        )
        return PDFUrlResponse(url=mock_url, expires_in_seconds=int(expiry.total_seconds()))


# ---------------------------------------------------------------------------
# 3.  GET /reports/{scan_job_id}/sarif  —  inline SARIF JSON
# ---------------------------------------------------------------------------
@reports_router.get("/{scan_job_id}/sarif")
def get_sarif_report(
    scan_job_id: str,
    db: Session = Depends(get_db),
    current_user: dict = require_permission("scan:read"),
):
    """Return a SARIF 2.1.0 JSON document for the scan job."""
    job = _get_scan_job_or_404(scan_job_id, db, current_user)
    findings = _get_findings_for_job(job.id, db)
    return _build_sarif(job, findings)


# ---------------------------------------------------------------------------
# 4.  GET /reports/{scan_job_id}/csv  —  downloadable CSV
# ---------------------------------------------------------------------------
@reports_router.get("/{scan_job_id}/csv")
def get_csv_report(
    scan_job_id: str,
    db: Session = Depends(get_db),
    current_user: dict = require_permission("scan:read"),
):
    """
    Return findings as a CSV file download.

    The response uses ``StreamingResponse`` with appropriate Content-Type
    and Content-Disposition headers.
    """
    job = _get_scan_job_or_404(scan_job_id, db, current_user)
    findings = _get_findings_for_job(job.id, db)

    # Build CSV in-memory
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "title", "severity", "sla_deadline", "scan_job_id", "organization_id"])
    for f in findings:
        writer.writerow([
            str(f.id),
            f.title,
            f.severity,
            f.sla_deadline.isoformat() if f.sla_deadline else "",
            str(f.scan_job_id),
            str(f.organization_id),
        ])

    buffer.seek(0)
    filename = f"report_{scan_job_id}.csv"

    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )
