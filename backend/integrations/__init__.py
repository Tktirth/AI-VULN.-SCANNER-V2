"""
Third-party integration modules for the AI Vulnerability Scanner V2.

Provides Slack, Jira, and generic webhook integrations for alerting
and issue tracking based on scan findings.
"""

from backend.integrations.slack import send_test_message, send_critical_finding_alert
from backend.integrations.jira import create_issue
from backend.integrations.webhooks import send_webhook
