"""
Slack integration for the AI Vulnerability Scanner V2.

Sends notifications to Slack channels via Incoming Webhook URLs.
Includes retry logic with exponential backoff for transient failures.
"""

import logging
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Retry configuration
MAX_RETRIES = 3
BACKOFF_BASE_SECONDS = 1  # 1s, 2s, 4s


def _post_with_retry(webhook_url: str, payload: dict) -> bool:
    """
    POST a JSON payload to a Slack webhook URL with retry logic.

    Retries up to MAX_RETRIES times with exponential backoff (1s, 2s, 4s)
    on network errors or non-200 responses.

    Args:
        webhook_url: The Slack Incoming Webhook URL.
        payload: The JSON body to send.

    Returns:
        True if the webhook accepted the payload (HTTP 200), False otherwise.
    """
    last_exception: Optional[Exception] = None

    for attempt in range(MAX_RETRIES):
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.post(webhook_url, json=payload)

            if response.status_code == 200:
                logger.info(
                    "Slack webhook delivered successfully on attempt %d",
                    attempt + 1,
                )
                return True

            logger.warning(
                "Slack webhook returned HTTP %d on attempt %d: %s",
                response.status_code,
                attempt + 1,
                response.text[:200],
            )

        except httpx.HTTPError as exc:
            last_exception = exc
            logger.warning(
                "Slack webhook request failed on attempt %d: %s",
                attempt + 1,
                str(exc),
            )

        # Exponential backoff: 1s, 2s, 4s (skip sleep after last attempt)
        if attempt < MAX_RETRIES - 1:
            sleep_seconds = BACKOFF_BASE_SECONDS * (2 ** attempt)
            logger.debug("Retrying Slack webhook in %ds…", sleep_seconds)
            time.sleep(sleep_seconds)

    logger.error(
        "Slack webhook delivery failed after %d attempts. Last error: %s",
        MAX_RETRIES,
        str(last_exception) if last_exception else "non-200 response",
    )
    return False


def send_test_message(webhook_url: str) -> bool:
    """
    Send a simple test message to verify a Slack webhook URL is valid.

    Args:
        webhook_url: The Slack Incoming Webhook URL to test.

    Returns:
        True if Slack responded with HTTP 200, False otherwise.
    """
    payload = {
        "text": "✅ AI Vulnerability Scanner V2 — Slack integration test successful!",
    }
    return _post_with_retry(webhook_url, payload)


def send_critical_finding_alert(
    webhook_url: str,
    finding: dict,
    scan_url: str,
) -> bool:
    """
    Send a rich Slack Block Kit notification for a critical/high-severity finding.

    Args:
        webhook_url: The Slack Incoming Webhook URL.
        finding: A dict containing at minimum: 'title', 'severity', 'id'.
                 Optional keys: 'sla_deadline', 'description'.
        scan_url: A URL linking back to the scan/finding in the dashboard.

    Returns:
        True if the message was delivered, False otherwise.
    """
    severity = finding.get("severity", "unknown").upper()
    title = finding.get("title", "Untitled Finding")
    finding_id = finding.get("id", "N/A")
    sla_deadline = finding.get("sla_deadline", "N/A")
    description = finding.get("description", "No additional details available.")

    # Severity-to-emoji mapping for visual cues
    severity_emoji = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
    }
    emoji = severity_emoji.get(severity, "⚪")

    payload = {
        "text": f"{emoji} [{severity}] New finding: {title}",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Security Finding — {severity}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Title:*\n{title}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{severity}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Finding ID:*\n`{finding_id}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*SLA Deadline:*\n{sla_deadline}",
                    },
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n{description}",
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "View Finding",
                            "emoji": True,
                        },
                        "url": scan_url,
                        "style": "primary",
                    },
                ],
            },
        ],
    }
    return _post_with_retry(webhook_url, payload)
