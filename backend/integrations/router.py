"""
FastAPI router for third-party integration endpoints.

All endpoints require ``org:write`` permission. The router is mounted at
``/integrations`` and exposes sub-paths for Slack, Jira, and webhooks.
"""

import logging
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.auth import require_permission
from backend.database import get_db
from backend.models import Finding

from backend.integrations.slack import send_test_message, send_critical_finding_alert
from backend.integrations.jira import create_issue
from backend.integrations.webhooks import send_webhook

logger = logging.getLogger(__name__)

integration_router = APIRouter(prefix="/integrations", tags=["integrations"])


# ---------------------------------------------------------------------------
# Pydantic request/response schemas
# ---------------------------------------------------------------------------

class SlackTestRequest(BaseModel):
    webhook_url: str = Field(..., description="Slack Incoming Webhook URL to test")


class SlackAlertRequest(BaseModel):
    webhook_url: str = Field(..., description="Slack Incoming Webhook URL")
    finding_id: str = Field(..., description="UUID of the finding to alert on")
    scan_url: str = Field(..., description="URL linking back to the finding in the UI")


class JiraCreateIssueRequest(BaseModel):
    jira_url: str = Field(..., description="Base Jira instance URL (e.g. https://myorg.atlassian.net)")
    project_key: str = Field(..., description="Jira project key (e.g. SEC)")
    api_token: str = Field(..., description="Jira Cloud API token")
    email: str = Field(..., description="Email associated with the Jira API token")
    finding_id: str = Field(..., description="UUID of the finding to create an issue for")


class JiraCreateIssueResponse(BaseModel):
    key: str = Field(..., description="Jira issue key (e.g. SEC-123)")
    id: str = Field(..., description="Jira issue ID")
    url: str = Field(..., description="Direct link to the created Jira issue")


class WebhookTestRequest(BaseModel):
    url: str = Field(..., description="Webhook destination URL")
    secret: str = Field(..., description="HMAC-SHA256 shared secret for signing")


# ---------------------------------------------------------------------------
# Slack endpoints
# ---------------------------------------------------------------------------

@integration_router.post(
    "/slack/test",
    status_code=status.HTTP_200_OK,
    summary="Test Slack webhook connectivity",
)
def test_slack_webhook(
    body: SlackTestRequest,
    current_user: dict = require_permission("org:write"),
):
    """Send a test message to verify a Slack webhook URL is valid and reachable."""
    logger.info(
        "User %s testing Slack webhook", current_user.get("email", "unknown")
    )
    success = send_test_message(body.webhook_url)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Slack webhook test failed after multiple retries. "
                   "Please verify the webhook URL is correct and active.",
        )
    return {"status": "ok", "message": "Slack test message sent successfully"}


@integration_router.post(
    "/slack/alert",
    status_code=status.HTTP_200_OK,
    summary="Send a Slack alert for a finding",
)
def send_slack_alert(
    body: SlackAlertRequest,
    db: Session = Depends(get_db),
    current_user: dict = require_permission("org:write"),
):
    """Look up a finding by ID and send a rich Slack Block Kit notification."""
    finding = _get_finding_with_access_check(body.finding_id, db, current_user)

    finding_dict = {
        "id": str(finding.id),
        "title": finding.title,
        "severity": finding.severity,
        "sla_deadline": finding.sla_deadline.isoformat() if finding.sla_deadline else "N/A",
    }
    success = send_critical_finding_alert(body.webhook_url, finding_dict, body.scan_url)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to deliver Slack alert after multiple retries.",
        )
    return {"status": "ok", "message": "Slack alert sent successfully"}


# ---------------------------------------------------------------------------
# Jira endpoints
# ---------------------------------------------------------------------------

@integration_router.post(
    "/jira/create-issue",
    response_model=JiraCreateIssueResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a Jira issue from a finding",
)
def create_jira_issue(
    body: JiraCreateIssueRequest,
    db: Session = Depends(get_db),
    current_user: dict = require_permission("org:write"),
):
    """
    Look up a finding by ID, create a corresponding Jira issue, and return
    the issue metadata (key, id, URL).
    """
    finding = _get_finding_with_access_check(body.finding_id, db, current_user)

    finding_dict = {
        "id": str(finding.id),
        "title": finding.title,
        "severity": finding.severity,
        "sla_deadline": finding.sla_deadline.isoformat() if finding.sla_deadline else "N/A",
        "scan_job_id": str(finding.scan_job_id),
    }

    try:
        result = create_issue(
            jira_url=body.jira_url,
            project_key=body.project_key,
            api_token=body.api_token,
            email=body.email,
            finding=finding_dict,
        )
    except Exception as exc:
        logger.error("Jira issue creation failed: %s", str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to create Jira issue: {str(exc)}",
        )

    logger.info(
        "Jira issue %s created by user %s for finding %s",
        result.get("key"),
        current_user.get("email", "unknown"),
        body.finding_id,
    )
    return result


# ---------------------------------------------------------------------------
# Webhook endpoints
# ---------------------------------------------------------------------------

@integration_router.post(
    "/webhooks/test",
    status_code=status.HTTP_200_OK,
    summary="Test a generic webhook endpoint",
)
def test_webhook(
    body: WebhookTestRequest,
    current_user: dict = require_permission("org:write"),
):
    """
    Send a signed test payload to verify a webhook endpoint is reachable
    and correctly validates HMAC-SHA256 signatures.
    """
    test_payload = {
        "event": "integration.test",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source": "ai-vulnerability-scanner-v2",
    }
    logger.info(
        "User %s testing webhook at %s",
        current_user.get("email", "unknown"),
        body.url,
    )
    success = send_webhook(body.url, test_payload, body.secret)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Webhook test failed after multiple retries. "
                   "Please verify the URL and that the endpoint accepts POST requests.",
        )
    return {"status": "ok", "message": "Webhook test payload delivered successfully"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_finding_with_access_check(
    finding_id: str,
    db: Session,
    current_user: dict,
) -> Finding:
    """
    Retrieve a Finding by UUID and enforce tenant-level access control.

    Raises HTTPException 404 if the finding doesn't exist, or 403 if the
    current user's organization doesn't own the finding.
    """
    try:
        finding_uuid = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid finding ID format: {finding_id}",
        )

    finding = db.query(Finding).filter(Finding.id == finding_uuid).first()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding {finding_id} not found",
        )

    # Tenant isolation: non-super-admins can only access their own org's findings
    if (
        current_user.get("role") != "super_admin"
        and current_user.get("organization_id") != str(finding.organization_id)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cannot access another organization's data",
        )

    return finding
