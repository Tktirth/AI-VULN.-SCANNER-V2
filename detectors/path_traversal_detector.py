"""
Path Traversal detector — V2.
Fuzzes inputs with path traversal payloads and checks if sensitive system files are returned.
"""

import re
import logging
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from typing import List, Dict, Any
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "C:\\windows\\win.ini"
]

PASSWD_PATTERNS = [
    r"root:x:0:0:",
    r"bin:x:1:1:"
]

WININI_PATTERNS = [
    r"\[extensions\]",
    r"\[fonts\]",
    r"\[files\]",
    r"\[mci extensions\]"
]


def detect_path_traversal(url: str, request_manager) -> List[Dict[str, Any]]:
    """
    Run path traversal detection on URL parameters and HTML forms.
    """
    vulns = []
    vulns.extend(_test_url_params(url, request_manager))
    vulns.extend(_test_forms(url, request_manager))
    return vulns


def _is_vulnerable(body: str, payload: str) -> bool:
    if "passwd" in payload.lower():
        for pat in PASSWD_PATTERNS:
            if re.search(pat, body, re.IGNORECASE):
                return True
    if "win.ini" in payload.lower():
        for pat in WININI_PATTERNS:
            if re.search(pat, body, re.IGNORECASE):
                return True
    return False


def _test_url_params(url: str, request_manager) -> List[Dict[str, Any]]:
    vulns = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return vulns

    for param_name in params:
        for payload in TRAVERSAL_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            test_url = (
                f"{parsed.scheme}://{parsed.netloc}"
                f"{parsed.path}?{urlencode(test_params)}"
            )
            try:
                resp = request_manager.get(test_url)
                if resp and _is_vulnerable(resp.text, payload):
                    vulns.append({
                        "type": "Path Traversal",
                        "subtype": "Local File Inclusion",
                        "url": url,
                        "parameter": param_name,
                        "payload": payload,
                        "method": "GET",
                        "evidence": f"Sensitive file content matched in response of {test_url}",
                        "description": (
                            f"Path Traversal detected via parameter '{param_name}'. "
                            f"Injected traversal string '{payload}' caused the application "
                            "to expose system configuration files."
                        ),
                        "remediation": (
                            "Avoid passing user-controlled file paths to file APIs. "
                            "Use a hardcoded list of allowed filenames (whitelist). "
                            "Sanitize path input using basename() equivalent APIs. "
                            "Run the application process in a chroot jail or container with limited file privileges."
                        ),
                    })
                    break
            except Exception as e:
                logger.debug(f"Path traversal URL param test error: {e}")

    return vulns


def _test_forms(url: str, request_manager) -> List[Dict[str, Any]]:
    vulns = []
    try:
        resp = request_manager.get(url)
        if not resp:
            return vulns
        soup = BeautifulSoup(resp.text, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action", url)
            method = form.get("method", "get").upper()
            form_url = urljoin(url, action)
            form_data = {}
            for inp in form.find_all(["input", "textarea"]):
                name = inp.get("name")
                itype = inp.get("type", "text").lower()
                if name and itype not in ("submit", "button", "reset", "hidden", "file"):
                    form_data[name] = inp.get("value", "test")

            if not form_data:
                continue

            for field in list(form_data.keys()):
                for payload in TRAVERSAL_PAYLOADS:
                    test_data = {**form_data, field: payload}
                    try:
                        if method == "POST":
                            r = request_manager.post(form_url, data=test_data)
                        else:
                            r = request_manager.get(form_url, params=test_data)
                        if r and _is_vulnerable(r.text, payload):
                            vulns.append({
                                "type": "Path Traversal",
                                "subtype": "Form-based Path Traversal",
                                "url": form_url,
                                "parameter": field,
                                "payload": payload,
                                "method": method,
                                "evidence": f"Sensitive file content matched in form response",
                                "description": (
                                    f"Path Traversal detected via form field '{field}' on {form_url}. "
                                    f"Submitting '{payload}' returned sensitive files."
                                ),
                                "remediation": (
                                    "Validate form inputs against an strict whitelist. "
                                    "Strip directory traversal characters (e.g. '../', '..\\')."
                                ),
                            })
                            break
                    except Exception as e:
                        logger.debug(f"Form Path Traversal test error: {e}")
    except Exception as e:
        logger.debug(f"Form extraction error for Path Traversal: {e}")
    return vulns
