"""
Directory and sensitive file discovery detector — V2.
Probes known sensitive paths and reports accessible resources.
"""

import logging
from urllib.parse import urlparse
from typing import List, Dict, Any

from utils.payloads import SENSITIVE_DIRECTORIES

logger = logging.getLogger(__name__)

INTERESTING_STATUS = {200, 201, 301, 302, 307}

CRITICAL_PATHS = {"/.env", "/.git/config", "/db.sql", "/database.sql", "/backup.zip", "/backup.tar.gz", "/phpinfo.php", "/web.config"}
ADMIN_PATHS = {"/admin", "/admin/", "/wp-admin", "/wp-admin/", "/administrator", "/phpmyadmin", "/console", "/dashboard"}
CONFIG_PATHS = {"/.git", "/.htaccess", "/config", "/server-status", "/server-info", "/swagger", "/swagger-ui.html"}


def detect_directories(base_url: str, request_manager) -> List[Dict[str, Any]]:
    vulns = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for path in SENSITIVE_DIRECTORIES:
        target = origin + path
        try:
            resp = request_manager.get(target, allow_redirects=False)
            if resp and resp.status_code in INTERESTING_STATUS:
                vuln = _build_vuln(target, path, resp.status_code)
                if vuln:
                    vulns.append(vuln)
        except Exception as e:
            logger.debug(f"Dir probe error [{target}]: {e}")

    return vulns


def _build_vuln(url: str, path: str, status: int) -> Dict[str, Any]:
    if path in CRITICAL_PATHS:
        subtype = "Sensitive File Exposed"
        desc = f"Critical file '{path}' is accessible. May expose credentials or server config."
        fix = f"Block access to '{path}' immediately. Remove from web root."
    elif path in ADMIN_PATHS:
        subtype = "Default/Admin Page Exposed"
        desc = f"Admin interface '{path}' returned HTTP {status}. Prime brute-force target."
        fix = "IP-restrict the admin panel. Enforce MFA. Move off public web root."
    elif path in CONFIG_PATHS:
        subtype = "Sensitive Directory Exposed"
        desc = f"Config path '{path}' returned HTTP {status}. May expose internal configuration."
        fix = f"Block '{path}' in server config. Move sensitive files outside the web root."
    elif "/api" in path or "/swagger" in path:
        subtype = "API Endpoint Exposed"
        desc = f"API or docs endpoint '{path}' is publicly accessible."
        fix = "Require authentication for all API endpoints. Disable Swagger in production."
    else:
        subtype = "Sensitive Directory Exposed"
        desc = f"Path '{path}' returned HTTP {status}."
        fix = f"Restrict access to '{path}'. Audit directory permissions."

    return {
        "type": "Directory Discovery",
        "subtype": subtype,
        "url": url,
        "parameter": path,
        "payload": "N/A",
        "method": "GET",
        "evidence": f"HTTP {status} from {url}",
        "description": desc,
        "remediation": fix,
    }
