"""
Internal-IP / hostname leakage detector — V2.

Scans HTTP response headers, HTML bodies, JavaScript files, and JSON
API responses for accidentally-exposed private IP addresses, loopback
addresses, and internal hostnames.

Follows the project's module-level-function detector pattern (see
``detectors/header_detector.py``).  All operations are synchronous.
Errors are caught internally — the function always returns a list of
finding dicts and never raises.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Private / internal IP patterns
# ---------------------------------------------------------------------------
_PRIVATE_IP_PATTERNS: List[re.Pattern] = [
    # IPv4 private ranges
    re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", re.IGNORECASE),
    re.compile(
        r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b", re.IGNORECASE
    ),
    re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b", re.IGNORECASE),
    # IPv4 loopback
    re.compile(r"\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", re.IGNORECASE),
    # IPv4 link-local
    re.compile(r"\b169\.254\.\d{1,3}\.\d{1,3}\b", re.IGNORECASE),
    # IPv6 loopback
    re.compile(r"\b::1\b", re.IGNORECASE),
    # IPv6 Unique Local Address (ULA)
    re.compile(r"\bfd[0-9a-f]{2}:[0-9a-f:]{2,}\b", re.IGNORECASE),
]

_INTERNAL_HOSTNAME_PATTERN: re.Pattern = re.compile(
    r"\b(?:internal|intranet|local|corp|private|backend|db|database|redis"
    r"|mongo|postgres|mysql|kafka|rabbit|elastic|cache|worker|admin)"
    r"-[a-z0-9\-]+\.[a-z]{2,}\b",
    re.IGNORECASE,
)

# Hardcoded internal-endpoint patterns for JavaScript scanning
_JS_INTERNAL_URL_PATTERNS: List[re.Pattern] = [
    re.compile(
        r"https?://(10|172\.1[6-9]|172\.2\d|172\.3[01]|192\.168)\.\d+\.\d+",
        re.IGNORECASE,
    ),
    re.compile(
        r"""[\"'`](https?://[a-z0-9\-]+\.(internal|local|corp|intranet))[/\"']""",
        re.IGNORECASE,
    ),
]

# ---------------------------------------------------------------------------
# Headers worth inspecting
# ---------------------------------------------------------------------------
HEADERS_TO_INSPECT: List[str] = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "X-Backend-Server",
    "X-Internal-IP",
    "X-Cluster-Client-IP",
    "X-Client-IP",
    "X-Host",
    "True-Client-IP",
    "Via",
    "Server",
    "X-Powered-By",
    "X-Varnish",
    "X-Cache",
    "X-Cache-Hits",
    "X-Request-ID",
    "X-Trace-ID",
]

# ---------------------------------------------------------------------------
# Finding template
# ---------------------------------------------------------------------------
_FINDING_TEMPLATE: Dict[str, Any] = {
    "type": "Information Disclosure",
    "subtype": "Internal IP Address Exposure",
    "severity": "Medium",
    "cvss_score": 5.3,
    "cwe_id": "CWE-200",
    "cwe_description": "Exposure of Sensitive Information to an Unauthorized Actor",
    "owasp_category": "A05:2021",
    "method": "GET",
    "payload": "N/A",
}


# ===================================================================== #
#  Public API — module-level function (matches project pattern)          #
# ===================================================================== #

def detect_ip_leakage(
    target_url: str,
    request_manager: Any,
    scanned_urls: List[str],
) -> List[Dict[str, Any]]:
    """Scan *scanned_urls* for leaked internal IPs and hostnames.

    Parameters
    ----------
    target_url:
        The base/target URL of the scan.
    request_manager:
        A ``RequestManager`` whose ``.get(url)`` returns
        ``Optional[requests.Response]``.
    scanned_urls:
        Previously-crawled URLs to inspect.

    Returns
    -------
    list[dict]
        Each dict follows the project's universal vulnerability format.
    """
    findings: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()  # (ip_or_hostname, category)

    try:
        # Source 1 — HTTP response headers
        findings.extend(
            _scan_headers(scanned_urls, request_manager, seen)
        )

        # Source 2 — HTML body text
        findings.extend(
            _scan_html_bodies(scanned_urls, request_manager, seen)
        )

        # Source 3 — JavaScript files
        findings.extend(
            _scan_javascript(scanned_urls, request_manager, seen)
        )

        # Source 4 — JSON API responses
        findings.extend(
            _scan_json_apis(scanned_urls, request_manager, seen)
        )
    except Exception as exc:
        logger.debug("detect_ip_leakage() top-level error: %s", exc)

    return findings


# ===================================================================== #
#  Source 1 — HTTP Response Headers                                      #
# ===================================================================== #

def _scan_headers(
    urls: List[str],
    request_manager: Any,
    seen: Set[Tuple[str, str]],
) -> List[Dict[str, Any]]:
    """Check response headers for private IPs / internal hostnames."""
    findings: List[Dict[str, Any]] = []
    try:
        for url in urls[:30]:
            try:
                resp = request_manager.get(url)
                if resp is None:
                    continue

                for header_name in HEADERS_TO_INSPECT:
                    value = resp.headers.get(header_name)
                    if not value:
                        continue

                    for pat in _PRIVATE_IP_PATTERNS:
                        match = pat.search(value)
                        if match:
                            ip = match.group(0)
                            key = (ip, "header")
                            if key in seen:
                                continue
                            seen.add(key)
                            findings.append(_build_finding(
                                url=url,
                                parameter=header_name,
                                evidence=f"{header_name}: {value}",
                                description=(
                                    f"Internal IP address '{ip}' leaked via "
                                    f"HTTP response header '{header_name}'."
                                ),
                            ))

                    hostname_match = _INTERNAL_HOSTNAME_PATTERN.search(value)
                    if hostname_match:
                        hn = hostname_match.group(0)
                        key = (hn, "header")
                        if key not in seen:
                            seen.add(key)
                            findings.append(_build_finding(
                                url=url,
                                parameter=header_name,
                                evidence=f"{header_name}: {value}",
                                description=(
                                    f"Internal hostname '{hn}' leaked via "
                                    f"HTTP response header '{header_name}'."
                                ),
                            ))
            except Exception as exc:
                logger.debug("Header scan error [%s]: %s", url, exc)
    except Exception as exc:
        logger.debug("_scan_headers() error: %s", exc)
    return findings


# ===================================================================== #
#  Source 2 — HTML Body                                                  #
# ===================================================================== #

def _scan_html_bodies(
    urls: List[str],
    request_manager: Any,
    seen: Set[Tuple[str, str]],
) -> List[Dict[str, Any]]:
    """Check HTML bodies and comments for private IPs."""
    findings: List[Dict[str, Any]] = []
    try:
        for url in urls[:30]:
            try:
                resp = request_manager.get(url)
                if resp is None:
                    continue
                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type.lower():
                    continue

                html = resp.text
                unique_count = 0

                # Scan full body
                for pat in _PRIVATE_IP_PATTERNS:
                    for match in pat.finditer(html):
                        if unique_count >= 5:
                            break
                        ip = match.group(0)
                        key = (ip, "html")
                        if key in seen:
                            continue
                        seen.add(key)
                        unique_count += 1
                        start = max(0, match.start() - 50)
                        end = min(len(html), match.end() + 50)
                        snippet = html[start:end].replace("\n", " ").strip()
                        findings.append(_build_finding(
                            url=url,
                            parameter="html_body",
                            evidence=f"IP '{ip}' in body: ...{snippet}...",
                            description=(
                                f"Internal IP address '{ip}' found in "
                                f"HTML body of {url}."
                            ),
                        ))

                # Scan HTML comments
                comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
                for comment in comments:
                    for pat in _PRIVATE_IP_PATTERNS:
                        match = pat.search(comment)
                        if match:
                            ip = match.group(0)
                            key = (ip, "html")
                            if key in seen:
                                continue
                            seen.add(key)
                            snippet = comment[:100].replace("\n", " ").strip()
                            findings.append(_build_finding(
                                url=url,
                                parameter="html_body",
                                evidence=(
                                    f"IP '{ip}' in HTML comment: "
                                    f"<!--{snippet}-->"
                                ),
                                description=(
                                    f"Internal IP address '{ip}' leaked "
                                    f"inside an HTML comment on {url}."
                                ),
                            ))

                    hostname_match = _INTERNAL_HOSTNAME_PATTERN.search(comment)
                    if hostname_match:
                        hn = hostname_match.group(0)
                        key = (hn, "html")
                        if key not in seen:
                            seen.add(key)
                            snippet = comment[:100].replace("\n", " ").strip()
                            findings.append(_build_finding(
                                url=url,
                                parameter="html_body",
                                evidence=(
                                    f"Hostname '{hn}' in HTML comment: "
                                    f"<!--{snippet}-->"
                                ),
                                description=(
                                    f"Internal hostname '{hn}' leaked "
                                    f"inside an HTML comment on {url}."
                                ),
                            ))
            except Exception as exc:
                logger.debug("HTML body scan error [%s]: %s", url, exc)
    except Exception as exc:
        logger.debug("_scan_html_bodies() error: %s", exc)
    return findings


# ===================================================================== #
#  Source 3 — JavaScript files                                           #
# ===================================================================== #

def _scan_javascript(
    urls: List[str],
    request_manager: Any,
    seen: Set[Tuple[str, str]],
) -> List[Dict[str, Any]]:
    """Extract <script src> URLs from HTML pages, fetch, and scan."""
    findings: List[Dict[str, Any]] = []
    try:
        js_urls: Set[str] = set()

        # Collect JS URLs from HTML pages
        for url in urls[:30]:
            try:
                resp = request_manager.get(url)
                if resp is None:
                    continue
                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type.lower():
                    continue
                for match in re.finditer(
                    r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.IGNORECASE
                ):
                    src = match.group(1)
                    absolute = urljoin(url, src)
                    js_urls.add(absolute)
            except Exception as exc:
                logger.debug("JS URL extraction error [%s]: %s", url, exc)

        # Fetch and scan each unique JS file (cap 20)
        for js_url in list(js_urls)[:20]:
            try:
                resp = request_manager.get(js_url)
                if resp is None:
                    continue
                js_text = resp.text

                # Private IP patterns
                for pat in _PRIVATE_IP_PATTERNS:
                    for match in pat.finditer(js_text):
                        ip = match.group(0)
                        key = (ip, "javascript")
                        if key in seen:
                            continue
                        seen.add(key)
                        start = max(0, match.start() - 50)
                        end = min(len(js_text), match.end() + 50)
                        snippet = js_text[start:end].replace("\n", " ").strip()
                        findings.append(_build_finding(
                            url=js_url,
                            parameter="javascript",
                            evidence=f"IP '{ip}' in JS: ...{snippet}...",
                            description=(
                                f"Internal IP address '{ip}' hard-coded "
                                f"in JavaScript file {js_url}."
                            ),
                        ))

                # Hardcoded internal endpoints
                for pat in _JS_INTERNAL_URL_PATTERNS:
                    for match in pat.finditer(js_text):
                        endpoint = match.group(0)
                        key = (endpoint, "javascript")
                        if key in seen:
                            continue
                        seen.add(key)
                        start = max(0, match.start() - 30)
                        end = min(len(js_text), match.end() + 30)
                        snippet = js_text[start:end].replace("\n", " ").strip()
                        findings.append(_build_finding(
                            url=js_url,
                            parameter="javascript",
                            evidence=(
                                f"Internal endpoint in JS: ...{snippet}..."
                            ),
                            description=(
                                f"Hardcoded internal endpoint '{endpoint}' "
                                f"found in JavaScript file {js_url}."
                            ),
                        ))
            except Exception as exc:
                logger.debug("JS scan error [%s]: %s", js_url, exc)
    except Exception as exc:
        logger.debug("_scan_javascript() error: %s", exc)
    return findings


# ===================================================================== #
#  Source 4 — JSON API Responses                                         #
# ===================================================================== #

def _scan_json_apis(
    urls: List[str],
    request_manager: Any,
    seen: Set[Tuple[str, str]],
) -> List[Dict[str, Any]]:
    """Inspect JSON responses for leaked private IPs."""
    findings: List[Dict[str, Any]] = []
    try:
        for url in urls[:30]:
            try:
                resp = request_manager.get(url)
                if resp is None:
                    continue
                content_type = resp.headers.get("Content-Type", "")
                if "application/json" not in content_type.lower():
                    continue

                try:
                    data = resp.json()
                except (json.JSONDecodeError, ValueError):
                    continue

                pairs = _extract_json_paths(data)
                for path, value in pairs[:50]:
                    for pat in _PRIVATE_IP_PATTERNS:
                        match = pat.search(value)
                        if match:
                            ip = match.group(0)
                            key = (ip, "json")
                            if key in seen:
                                continue
                            seen.add(key)
                            findings.append(_build_finding(
                                url=url,
                                parameter="api_response",
                                evidence=(
                                    f"IP '{ip}' at JSON path '{path}': "
                                    f"{value[:100]}"
                                ),
                                description=(
                                    f"Internal IP address '{ip}' leaked in "
                                    f"JSON API response from {url} "
                                    f"(path: {path})."
                                ),
                            ))

                    hostname_match = _INTERNAL_HOSTNAME_PATTERN.search(value)
                    if hostname_match:
                        hn = hostname_match.group(0)
                        key = (hn, "json")
                        if key not in seen:
                            seen.add(key)
                            findings.append(_build_finding(
                                url=url,
                                parameter="api_response",
                                evidence=(
                                    f"Hostname '{hn}' at JSON path '{path}': "
                                    f"{value[:100]}"
                                ),
                                description=(
                                    f"Internal hostname '{hn}' leaked in "
                                    f"JSON API response from {url} "
                                    f"(path: {path})."
                                ),
                            ))
            except Exception as exc:
                logger.debug("JSON scan error [%s]: %s", url, exc)
    except Exception as exc:
        logger.debug("_scan_json_apis() error: %s", exc)
    return findings


# ===================================================================== #
#  Helpers                                                               #
# ===================================================================== #

def _extract_json_paths(
    obj: Any, path: str = ""
) -> List[Tuple[str, str]]:
    """Recursively walk *obj* and yield ``(dotted_path, string_value)`` pairs."""
    results: List[Tuple[str, str]] = []
    try:
        if isinstance(obj, dict):
            for key, val in obj.items():
                new_path = f"{path}.{key}" if path else key
                results.extend(_extract_json_paths(val, new_path))
        elif isinstance(obj, list):
            for idx, val in enumerate(obj):
                new_path = f"{path}[{idx}]"
                results.extend(_extract_json_paths(val, new_path))
        elif isinstance(obj, str):
            results.append((path, obj))
    except Exception:
        pass
    return results


def _build_finding(
    url: str,
    parameter: str,
    evidence: str,
    description: str,
) -> Dict[str, Any]:
    """Return a vulnerability dict in the project's standard format."""
    finding = dict(_FINDING_TEMPLATE)
    finding["url"] = url
    finding["parameter"] = parameter
    finding["evidence"] = evidence
    finding["description"] = description
    finding["remediation"] = (
        "Remove internal IP addresses and hostnames from HTTP responses. "
        "Configure reverse proxies and load balancers to strip internal "
        "headers (X-Forwarded-For, X-Real-IP, etc.). Sanitise HTML "
        "comments and JavaScript bundles before deployment."
    )
    return finding
