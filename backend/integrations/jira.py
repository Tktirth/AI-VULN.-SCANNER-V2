"""
Jira integration for the AI Vulnerability Scanner V2.

Creates Jira issues from scan findings using the Jira Cloud REST API v3.
Authenticates via Basic Auth (email + API token).
"""

import logging
from typing import Dict, Optional

import httpx

logger = logging.getLogger(__name__)

# Maps scanner severity levels to Jira priority names.
# Jira Cloud ships with: Highest, High, Medium, Low, Lowest.
SEVERITY_TO_PRIORITY: Dict[str, str] = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


def create_issue(
    jira_url: str,
    project_key: str,
    api_token: str,
    email: str,
    finding: dict,
) -> dict:
    """
    Create a Jira issue from a vulnerability finding.

    Sends a POST to Jira's REST API v3 to create a new Bug-type issue with
    severity-mapped priority and a structured description.

    Args:
        jira_url: Base URL of the Jira instance (e.g. 'https://myorg.atlassian.net').
        project_key: The Jira project key (e.g. 'SEC').
        api_token: Jira Cloud API token for authentication.
        email: Email address associated with the Jira API token.
        finding: Dict with at minimum 'title', 'severity', 'id'.
                 Optional keys: 'sla_deadline', 'description', 'scan_job_id'.

    Returns:
        A dict containing:
          - 'key': The created issue key (e.g. 'SEC-123').
          - 'id': The Jira issue ID.
          - 'url': Direct link to the created issue.

    Raises:
        httpx.HTTPStatusError: If the Jira API returns a non-2xx response.
        httpx.HTTPError: On network-level failures.
    """
    severity = (finding.get("severity") or "low").lower()
    priority_name = SEVERITY_TO_PRIORITY.get(severity, "Medium")

    title = finding.get("title", "Untitled Finding")
    finding_id = finding.get("id", "N/A")
    sla_deadline = finding.get("sla_deadline", "N/A")
    description_text = finding.get("description", "No additional details.")
    scan_job_id = finding.get("scan_job_id", "N/A")

    # Jira Cloud REST API v3 uses Atlassian Document Format (ADF) for descriptions.
    issue_payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": f"[{severity.upper()}] {title}",
            "issuetype": {"name": "Bug"},
            "priority": {"name": priority_name},
            "description": {
                "version": 1,
                "type": "doc",
                "content": [
                    {
                        "type": "heading",
                        "attrs": {"level": 3},
                        "content": [
                            {"type": "text", "text": "Vulnerability Details"},
                        ],
                    },
                    {
                        "type": "table",
                        "attrs": {"layout": "default"},
                        "content": [
                            _table_row("Finding ID", str(finding_id)),
                            _table_row("Severity", severity.upper()),
                            _table_row("Priority", priority_name),
                            _table_row("SLA Deadline", str(sla_deadline)),
                            _table_row("Scan Job ID", str(scan_job_id)),
                        ],
                    },
                    {
                        "type": "heading",
                        "attrs": {"level": 3},
                        "content": [
                            {"type": "text", "text": "Description"},
                        ],
                    },
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": description_text},
                        ],
                    },
                ],
            },
            "labels": [
                "vulnerability",
                f"severity-{severity}",
                "ai-vuln-scanner",
            ],
        },
    }

    # Strip trailing slash from jira_url to avoid double-slash in the path
    base_url = jira_url.rstrip("/")
    api_endpoint = f"{base_url}/rest/api/3/issue"

    logger.info(
        "Creating Jira issue in project %s for finding %s (severity=%s)",
        project_key,
        finding_id,
        severity,
    )

    with httpx.Client(timeout=30.0) as client:
        response = client.post(
            api_endpoint,
            json=issue_payload,
            auth=(email, api_token),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        response.raise_for_status()

    result = response.json()
    issue_key = result.get("key", "UNKNOWN")
    issue_id = result.get("id", "")
    issue_url = f"{base_url}/browse/{issue_key}"

    logger.info(
        "Jira issue %s created successfully (id=%s)",
        issue_key,
        issue_id,
    )

    return {
        "key": issue_key,
        "id": issue_id,
        "url": issue_url,
    }


def _table_row(label: str, value: str) -> dict:
    """Build a single ADF table row with a label cell and a value cell."""
    return {
        "type": "tableRow",
        "content": [
            {
                "type": "tableCell",
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": label,
                                "marks": [{"type": "strong"}],
                            },
                        ],
                    },
                ],
            },
            {
                "type": "tableCell",
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": value},
                        ],
                    },
                ],
            },
        ],
    }
