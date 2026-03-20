"""
Security header detector — V2.
Checks HTTP response headers for missing, weak, or info-leaking values.
"""

import logging
from typing import List, Dict, Any

from utils.payloads import SECURITY_HEADERS

logger = logging.getLogger(__name__)

HEADER_VALUE_CHECKS = {
    "X-Content-Type-Options": {
        "required_value": "nosniff",
        "weak_note": "Must be exactly 'nosniff'",
    },
    "Strict-Transport-Security": {
        "required_contains": "max-age",
        "weak_note": "Missing max-age directive",
    },
}


def detect_missing_headers(url: str, request_manager) -> List[Dict[str, Any]]:
    vulns = []
    try:
        resp = request_manager.get(url)
        if not resp:
            return vulns

        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        for header_name, info in SECURITY_HEADERS.items():
            key = header_name.lower()
            if key not in resp_headers:
                vulns.append({
                    "type": "Missing Security Header",
                    "subtype": f"Missing {header_name}",
                    "url": url,
                    "parameter": header_name,
                    "payload": "N/A",
                    "method": "GET",
                    "evidence": f"'{header_name}' absent from HTTP response",
                    "description": f"'{header_name}' is missing. {info['description']}.",
                    "remediation": f"Add: {header_name}: {info['recommended']}",
                })
            else:
                current = resp_headers[key]
                check = HEADER_VALUE_CHECKS.get(header_name)
                if check:
                    if "required_value" in check and current.strip().lower() != check["required_value"]:
                        vulns.append(_weak_header(url, header_name, current, check["weak_note"], info["recommended"]))
                    elif "required_contains" in check and check["required_contains"] not in current.lower():
                        vulns.append(_weak_header(url, header_name, current, check["weak_note"], info["recommended"]))

        vulns.extend(_check_info_leakage(resp_headers, url))

    except Exception as e:
        logger.debug(f"Header check error [{url}]: {e}")
    return vulns


def _weak_header(url, name, current_value, note, recommended):
    return {
        "type": "Weak Security Header",
        "subtype": f"Weak {name}",
        "url": url,
        "parameter": name,
        "payload": "N/A",
        "method": "GET",
        "evidence": f"{name}: {current_value}",
        "description": f"'{name}' has a weak value. {note}.",
        "remediation": f"Change to: {name}: {recommended}",
    }


def _check_info_leakage(headers: Dict[str, str], url: str) -> List[Dict[str, Any]]:
    leaky = {
        "server": "Reveals server software and version",
        "x-powered-by": "Exposes backend technology",
        "x-aspnet-version": "Reveals ASP.NET version",
        "x-aspnetmvc-version": "Reveals ASP.NET MVC version",
        "x-generator": "Reveals CMS or framework",
    }
    vulns = []
    for header, desc in leaky.items():
        if header in headers:
            vulns.append({
                "type": "Information Disclosure",
                "subtype": "Server Information Leakage",
                "url": url,
                "parameter": header,
                "payload": "N/A",
                "method": "GET",
                "evidence": f"{header}: {headers[header]}",
                "description": f"Header '{header}' leaks server info. {desc}.",
                "remediation": f"Remove or suppress the '{header}' header in server config.",
            })
    return vulns
