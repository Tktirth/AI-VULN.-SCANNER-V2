"""
Generic webhook integration for the AI Vulnerability Scanner V2.

Sends signed JSON payloads to arbitrary webhook endpoints with
HMAC-SHA256 verification and retry logic.
"""

import hashlib
import hmac
import json
import logging
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Retry configuration
MAX_RETRIES = 3
BACKOFF_BASE_SECONDS = 1  # 1s, 2s, 4s
REQUEST_TIMEOUT_SECONDS = 10.0


def _compute_signature(body: bytes, secret: str) -> str:
    """
    Compute an HMAC-SHA256 hex digest of the request body.

    Args:
        body: The raw JSON-encoded request body bytes.
        secret: The shared secret used for HMAC signing.

    Returns:
        A hex-encoded HMAC-SHA256 signature string prefixed with 'sha256='.
    """
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def send_webhook(url: str, payload: dict, secret: str) -> bool:
    """
    Send a signed JSON webhook payload to the given URL.

    The payload is serialized to JSON, then signed with HMAC-SHA256 using
    the provided secret. The signature is placed in the ``X-Webhook-Signature``
    header so receivers can verify authenticity.

    Retries up to 3 times with exponential backoff (1s, 2s, 4s) on network
    errors or non-2xx HTTP responses.

    Args:
        url: The destination webhook URL.
        payload: The dict to serialize and send as the JSON body.
        secret: The shared secret for HMAC-SHA256 signing.

    Returns:
        True if the webhook was delivered successfully (HTTP 2xx),
        False after all retries are exhausted.
    """
    # Serialize once so the signature matches the exact bytes sent
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = _compute_signature(body, secret)

    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Signature": signature,
    }

    last_exception: Optional[Exception] = None

    for attempt in range(MAX_RETRIES):
        try:
            with httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS) as client:
                response = client.post(url, content=body, headers=headers)

            if 200 <= response.status_code < 300:
                logger.info(
                    "Webhook delivered successfully to %s on attempt %d (HTTP %d)",
                    url,
                    attempt + 1,
                    response.status_code,
                )
                return True

            logger.warning(
                "Webhook to %s returned HTTP %d on attempt %d: %s",
                url,
                response.status_code,
                attempt + 1,
                response.text[:200],
            )

        except httpx.HTTPError as exc:
            last_exception = exc
            logger.warning(
                "Webhook request to %s failed on attempt %d: %s",
                url,
                attempt + 1,
                str(exc),
            )

        # Exponential backoff: 1s, 2s, 4s (skip sleep after last attempt)
        if attempt < MAX_RETRIES - 1:
            sleep_seconds = BACKOFF_BASE_SECONDS * (2 ** attempt)
            logger.debug("Retrying webhook to %s in %ds…", url, sleep_seconds)
            time.sleep(sleep_seconds)

    logger.error(
        "Webhook delivery to %s failed after %d attempts. Last error: %s",
        url,
        MAX_RETRIES,
        str(last_exception) if last_exception else "non-2xx response",
    )
    return False
