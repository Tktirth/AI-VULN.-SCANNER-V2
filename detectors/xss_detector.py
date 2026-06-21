"""
XSS detector — V2.
Covers reflected XSS (URL params + forms) and stored XSS via two-pass detection.

Two-pass stored XSS:
  Pass 1 — submit a uniquely marked payload into every form input
  Pass 2 — revisit the same page (and related pages) to check if the
            marker was persisted and rendered back in the HTML
"""

import re
import logging
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from typing import List, Dict, Any

from bs4 import BeautifulSoup
from utils.payloads import XSS_PAYLOADS, STORED_XSS_PAYLOADS, STORED_XSS_MARKER

logger = logging.getLogger(__name__)

XSS_REFLECTION_PATTERNS = [
    r"<script[^>]*>.*?alert",
    r"onerror\s*=\s*['\"]?alert",
    r"onload\s*=\s*['\"]?alert",
    r"<svg[^>]*onload",
    r"javascript:alert",
    r"<img[^>]*onerror",
    r"<iframe[^>]*src\s*=\s*['\"]?javascript",
    r"String\.fromCharCode\(88,83,83\)",
    r"<details[^>]*ontoggle",
    r"autofocus[^>]*onfocus",
]


def detect_xss(url: str, request_manager) -> List[Dict[str, Any]]:
    """
    Run reflected XSS detection on URL parameters and HTML forms.

    Args:
        url: Target page URL
        request_manager: Authenticated or plain RequestManager

    Returns:
        List of vulnerability dicts
    """
    vulns = []
    vulns.extend(_test_url_params(url, request_manager))
    vulns.extend(_test_forms_reflected(url, request_manager))
    return vulns


def detect_stored_xss(
    url: str,
    request_manager,
    pages_to_check: List[str],
) -> List[Dict[str, Any]]:
    """
    Two-pass stored XSS detection.

    Pass 1: Submit marked payloads into all form inputs on the target page.
    Pass 2: Revisit the page and a list of related pages to check if the
            marker appears in any rendered HTML response.

    Args:
        url: Page containing the form to inject into
        request_manager: Session-carrying RequestManager
        pages_to_check: List of URLs to scan for stored payload reflection

    Returns:
        List of stored XSS vulnerability dicts
    """
    vulns = []
    injected_fields = _inject_stored_payloads(url, request_manager)

    if not injected_fields:
        return vulns

    # Pass 2: check for marker in all provided pages
    for check_url in pages_to_check:
        try:
            resp = request_manager.get(check_url)
            if resp and STORED_XSS_MARKER in resp.text:
                for field_info in injected_fields:
                    vulns.append({
                        "type": "Stored XSS",
                        "subtype": "Stored XSS",
                        "url": check_url,
                        "injected_at": url,
                        "parameter": field_info["field"],
                        "payload": field_info["payload"],
                        "method": "POST",
                        "evidence": f"Stored XSS marker '{STORED_XSS_MARKER}' found in {check_url}",
                        "description": (
                            f"Stored XSS confirmed. A payload submitted to form field "
                            f"'{field_info['field']}' on {url} was later rendered "
                            f"unescaped at {check_url}. Any visitor to that page "
                            f"would execute the injected script."
                        ),
                        "remediation": (
                            "Sanitize and encode all user-supplied data before storing it. "
                            "Apply HTML entity encoding on every output point. "
                            "Implement a strict Content-Security-Policy."
                        ),
                    })
                break  # One confirmed stored XSS per injection URL is enough
        except Exception as e:
            logger.debug(f"Stored XSS pass-2 error on {check_url}: {e}")

    return vulns


# ── Private helpers ───────────────────────────────────────────────────────────

def _test_url_params(url: str, request_manager) -> List[Dict[str, Any]]:
    vulns = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return vulns

    for param_name in params:
        for payload in XSS_PAYLOADS[:6]:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            test_url = (
                f"{parsed.scheme}://{parsed.netloc}"
                f"{parsed.path}?{urlencode(test_params)}"
            )
            try:
                resp = request_manager.get(test_url)
                if resp and _is_reflected(payload, resp.text):
                    vulns.append({
                        "type": "XSS",
                        "subtype": "Reflected XSS",
                        "url": url,
                        "parameter": param_name,
                        "payload": payload,
                        "method": "GET",
                        "evidence": "Payload reflected in response without encoding",
                        "description": (
                            f"Reflected XSS in parameter '{param_name}'. "
                            "User input is echoed back into HTML without encoding, "
                            "allowing arbitrary script injection."
                        ),
                        "remediation": (
                            "HTML-encode all output. "
                            "Implement Content-Security-Policy. "
                            "Validate input server-side."
                        ),
                    })
                    break
            except Exception as e:
                logger.debug(f"XSS URL param test error: {e}")

    return vulns


def _test_forms_reflected(url: str, request_manager) -> List[Dict[str, Any]]:
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
            form_data = _build_form_data(form)
            if not form_data:
                continue

            for field in list(form_data.keys()):
                for payload in XSS_PAYLOADS[:4]:
                    test_data = {**form_data, field: payload}
                    try:
                        if method == "POST":
                            r = request_manager.post(form_url, data=test_data)
                        else:
                            r = request_manager.get(form_url, params=test_data)
                        if r and _is_reflected(payload, r.text):
                            vulns.append({
                                "type": "XSS",
                                "subtype": "Form-based Reflected XSS",
                                "url": form_url,
                                "parameter": field,
                                "payload": payload,
                                "method": method,
                                "evidence": "Form input reflected in response",
                                "description": (
                                    f"Reflected XSS in form field '{field}' on {form_url}. "
                                    "The input is returned unescaped in the server response."
                                ),
                                "remediation": (
                                    "Encode all form output before rendering. "
                                    "Use framework-level escaping."
                                ),
                            })
                            break
                    except Exception as e:
                        logger.debug(f"Form XSS test error: {e}")
    except Exception as e:
        logger.debug(f"Form extraction error for {url}: {e}")
    return vulns


def _inject_stored_payloads(url: str, request_manager) -> List[Dict[str, str]]:
    """
    Submit stored XSS payloads into all form fields on the page.
    Returns list of {field, payload} dicts for the fields we injected into.
    """
    injected = []
    try:
        resp = request_manager.get(url)
        if not resp:
            return injected
        soup = BeautifulSoup(resp.text, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action", url)
            method = form.get("method", "post").upper()
            form_url = urljoin(url, action)
            form_data = _build_form_data(form)
            if not form_data:
                continue

            for field in list(form_data.keys()):
                payload = STORED_XSS_PAYLOADS[0]
                test_data = {**form_data, field: payload}
                try:
                    if method == "POST":
                        request_manager.post(form_url, data=test_data)
                    else:
                        request_manager.get(form_url, params=test_data)
                    injected.append({"field": field, "payload": payload, "form_url": form_url})
                except Exception as e:
                    logger.debug(f"Stored XSS injection error: {e}")
    except Exception as e:
        logger.debug(f"Stored XSS pass-1 error for {url}: {e}")
    return injected


def _build_form_data(form) -> Dict[str, str]:
    data = {}
    for inp in form.find_all(["input", "textarea"]):
        name = inp.get("name")
        itype = inp.get("type", "text").lower()
        if name and itype not in ("submit", "button", "reset", "hidden", "file"):
            data[name] = inp.get("value", "test")
    return data


def _is_reflected(payload: str, body: str) -> bool:
    if payload in body:
        return True
    for pattern in XSS_REFLECTION_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
            return True
    return False
