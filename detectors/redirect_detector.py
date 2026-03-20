"""
Open Redirect detector — V2.
Tests redirect parameters for unvalidated external redirect behavior.
"""

import re
import logging
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
from typing import List, Dict, Any, Optional

from utils.payloads import OPEN_REDIRECT_PAYLOADS, REDIRECT_PARAMS

logger = logging.getLogger(__name__)
EVIL_DOMAIN = "evil.com"


def detect_open_redirect(url: str, request_manager) -> List[Dict[str, Any]]:
    vulns = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for param_name in REDIRECT_PARAMS:
        vuln = _test_redirect_param(url, param_name, parsed, params, request_manager)
        if vuln:
            vulns.append(vuln)

    return vulns


def _test_redirect_param(url, param_name, parsed, original_params, rm):
    for payload in OPEN_REDIRECT_PAYLOADS[:4]:
        test_params = {k: v[0] for k, v in original_params.items()}
        test_params[param_name] = payload
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
        try:
            resp = rm.get(test_url, allow_redirects=False)
            if not resp:
                continue

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if EVIL_DOMAIN in location or _is_external(location, url):
                    return {
                        "type": "Open Redirect",
                        "subtype": "Unvalidated Redirect",
                        "url": url,
                        "parameter": param_name,
                        "payload": payload,
                        "method": "GET",
                        "evidence": f"HTTP {resp.status_code} → Location: {location}",
                        "description": (
                            f"Open redirect via parameter '{param_name}'. "
                            f"Server redirects to '{location}' without validation."
                        ),
                        "remediation": (
                            "Validate redirect destinations against a whitelist. "
                            "Use relative paths. Reject external domains."
                        ),
                    }

            if resp.status_code == 200 and _check_meta_redirect(resp.text, payload):
                return {
                    "type": "Open Redirect",
                    "subtype": "Client-side Redirect",
                    "url": url,
                    "parameter": param_name,
                    "payload": payload,
                    "method": "GET",
                    "evidence": "Meta-refresh or JS redirect to user-supplied URL",
                    "description": (
                        f"Client-side open redirect in '{param_name}'. "
                        "Page contains a meta or JS redirect to the user-supplied value."
                    ),
                    "remediation": "Validate redirect targets server-side. Never use client redirects with user input.",
                }
        except Exception as e:
            logger.debug(f"Redirect test error [{param_name}]: {e}")
    return None


def _is_external(location: str, original_url: str) -> bool:
    if not location:
        return False
    try:
        loc = urlparse(location)
        orig = urlparse(original_url)
        return bool(loc.netloc) and loc.netloc != orig.netloc
    except Exception:
        return False


def _check_meta_redirect(html: str, payload: str) -> bool:
    patterns = [
        r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\']+)',
        r'window\.location\s*=\s*["\']([^"\']+)',
        r'window\.location\.href\s*=\s*["\']([^"\']+)',
    ]
    for p in patterns:
        m = re.search(p, html, re.IGNORECASE)
        if m and (EVIL_DOMAIN in m.group(1) or payload in m.group(0)):
            return True
    return False
