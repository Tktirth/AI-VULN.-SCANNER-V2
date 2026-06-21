import socket
import logging
import ipaddress
import uuid
from urllib.parse import urlparse
from typing import Optional
from fastapi import HTTPException
from sqlalchemy.orm import Session

from backend.models import AuditLog

logger = logging.getLogger(__name__)

def is_ssrf_safe(url: str) -> bool:
    """
    Checks if a URL resolves to a safe, public IP address (not loopback, private, or link-local).
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
            
        # Resolve hostname to IP addresses
        addr_info = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            ip = ipaddress.ip_address(ip_str)
            
            # Block private, loopback, link-local, multicast, or unspecified IPs
            if (
                ip.is_private or
                ip.is_loopback or
                ip.is_link_local or
                ip.is_multicast or
                ip.is_unspecified
            ):
                logger.warning(f"SSRF block triggered: {url} resolved to blocked IP {ip_str}")
                return False
                
        return True
    except Exception as e:
        logger.error(f"Error checking SSRF safety for {url}: {e}")
        return False

def validate_scan_target(
    url: str,
    authorization_confirmed: bool,
    user_id: Optional[str],
    organization_id: str,
    db: Session
):
    """
    Validates a target URL against SSRF and checks authorization consent.
    If validation fails, logs the event to audit_logs and raises 400.
    """
    if not authorization_confirmed:
        raise HTTPException(
            status_code=400,
            detail="Scan submission rejected: authorization_confirmed must be true"
        )
        
    if not is_ssrf_safe(url):
        # Resolve IP for logging details if possible
        resolved_ip = "Unknown"
        try:
            parsed = urlparse(url)
            if parsed.hostname:
                resolved_ip = socket.gethostbyname(parsed.hostname)
        except Exception:
            pass

        # Write to audit_logs
        audit_entry = AuditLog(
            action="SSRF_ATTEMPT_BLOCKED",
            details={
                "target_url": url,
                "resolved_ip": resolved_ip,
                "reason": "Target resolved to loopback, private, or link-local range"
            },
            user_id=uuid.UUID(user_id) if user_id else None,
            organization_id=uuid.UUID(organization_id) if isinstance(organization_id, str) else organization_id
        )
        db.add(audit_entry)
        db.commit()
        
        raise HTTPException(
            status_code=400,
            detail="SSRF Blocked: Scanning local or private network targets is prohibited"
        )
