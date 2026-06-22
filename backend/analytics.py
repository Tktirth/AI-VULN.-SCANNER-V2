"""
Analytics endpoints for the AI Vulnerability Scanner V2.

Provides aggregated statistics, severity trends over time, and SLA breach
reporting.  All endpoints require the ``finding:read`` permission and enforce
organisation-level tenant isolation for non-super_admin users.
"""

import uuid
from datetime import datetime, timedelta
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, cast, Date
from sqlalchemy.orm import Session

from backend.auth import require_permission, get_current_user
from backend.database import get_db
from backend.models import Finding, ScanJob


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
analytics_router = APIRouter(prefix="/analytics", tags=["analytics"])


# ---------------------------------------------------------------------------
# Pydantic response schemas
# ---------------------------------------------------------------------------
class TrendEntry(BaseModel):
    date: str
    critical: int
    high: int
    medium: int
    low: int


class SLABreachedFinding(BaseModel):
    id: str
    title: str
    severity: str
    sla_deadline: str
    days_overdue: int


class SLAStatusResponse(BaseModel):
    breached: List[SLABreachedFinding]
    total_breached: int


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class SummaryResponse(BaseModel):
    total_scans: int
    total_findings: int
    severity_breakdown: SeverityBreakdown
    avg_findings_per_scan: float


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _org_filter_findings(query, current_user: dict):
    """Apply organisation-level tenant isolation to a Finding query."""
    if current_user["role"] != "super_admin":
        org_id = uuid.UUID(current_user["organization_id"])
        query = query.filter(Finding.organization_id == org_id)
    return query


def _org_filter_scans(query, current_user: dict):
    """Apply organisation-level tenant isolation to a ScanJob query."""
    if current_user["role"] != "super_admin":
        org_id = uuid.UUID(current_user["organization_id"])
        query = query.filter(ScanJob.organization_id == org_id)
    return query


# ---------------------------------------------------------------------------
# 1.  GET /analytics/trend?days=30
# ---------------------------------------------------------------------------
@analytics_router.get("/trend", response_model=List[TrendEntry])
def get_trend(
    days: int = Query(default=30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: dict = require_permission("finding:read"),
):
    """
    Return an array of ``days`` entries (one per day) with severity counts.

    Days that have no findings are included with all-zero counts so the
    frontend can render a continuous time-series chart without gaps.
    """
    today = datetime.utcnow().date()
    start_date = today - timedelta(days=days - 1)

    # Query daily severity counts within the date window
    query = (
        db.query(
            cast(Finding.sla_deadline, Date).label("day"),
            Finding.severity,
            func.count(Finding.id).label("cnt"),
        )
        .filter(cast(Finding.sla_deadline, Date) >= start_date)
        .filter(cast(Finding.sla_deadline, Date) <= today)
    )
    query = _org_filter_findings(query, current_user)
    query = query.group_by(cast(Finding.sla_deadline, Date), Finding.severity)

    rows = query.all()

    # Build a lookup:  date_str -> {severity: count}
    counts: dict = {}
    for row in rows:
        day_str = row.day.isoformat() if hasattr(row.day, "isoformat") else str(row.day)
        sev = (row.severity or "low").lower()
        counts.setdefault(day_str, {"critical": 0, "high": 0, "medium": 0, "low": 0})
        if sev in counts[day_str]:
            counts[day_str][sev] += row.cnt

    # Build the contiguous list (always exactly `days` entries)
    result: List[TrendEntry] = []
    for offset in range(days):
        d = start_date + timedelta(days=offset)
        d_str = d.isoformat()
        entry = counts.get(d_str, {"critical": 0, "high": 0, "medium": 0, "low": 0})
        result.append(TrendEntry(date=d_str, **entry))

    return result


# ---------------------------------------------------------------------------
# 2.  GET /analytics/sla-status
# ---------------------------------------------------------------------------
@analytics_router.get("/sla-status", response_model=SLAStatusResponse)
def get_sla_status(
    db: Session = Depends(get_db),
    current_user: dict = require_permission("finding:read"),
):
    """
    Return all findings whose SLA deadline has already passed (breached).
    """
    now = datetime.utcnow()

    query = db.query(Finding).filter(Finding.sla_deadline < now)
    query = _org_filter_findings(query, current_user)

    breached_findings = query.all()

    breached = []
    for f in breached_findings:
        days_overdue = (now - f.sla_deadline).days
        breached.append(
            SLABreachedFinding(
                id=str(f.id),
                title=f.title,
                severity=f.severity,
                sla_deadline=f.sla_deadline.isoformat(),
                days_overdue=days_overdue,
            )
        )

    return SLAStatusResponse(breached=breached, total_breached=len(breached))


# ---------------------------------------------------------------------------
# 3.  GET /analytics/summary
# ---------------------------------------------------------------------------
@analytics_router.get("/summary", response_model=SummaryResponse)
def get_summary(
    db: Session = Depends(get_db),
    current_user: dict = require_permission("finding:read"),
):
    """
    Return high-level statistics: total scans, total findings, severity
    breakdown, and average findings per scan.
    """
    # Total scans
    scan_query = db.query(func.count(ScanJob.id))
    scan_query = _org_filter_scans(scan_query, current_user)
    total_scans: int = scan_query.scalar() or 0

    # Total findings
    finding_query = db.query(func.count(Finding.id))
    finding_query = _org_filter_findings(finding_query, current_user)
    total_findings: int = finding_query.scalar() or 0

    # Severity breakdown
    breakdown_query = (
        db.query(Finding.severity, func.count(Finding.id).label("cnt"))
        .group_by(Finding.severity)
    )
    breakdown_query = _org_filter_findings(breakdown_query, current_user)

    breakdown = SeverityBreakdown()
    for row in breakdown_query.all():
        sev = (row.severity or "low").lower()
        if sev in ("critical", "high", "medium", "low"):
            setattr(breakdown, sev, row.cnt)

    # Average findings per scan
    avg = round(total_findings / total_scans, 2) if total_scans else 0.0

    return SummaryResponse(
        total_scans=total_scans,
        total_findings=total_findings,
        severity_breakdown=breakdown,
        avg_findings_per_scan=avg,
    )
