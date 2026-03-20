"""
SQL injection detector — V2.
Error-based, boolean-based, and form-based detection.
"""

import re
import logging
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from typing import List, Dict, Any

from bs4 import BeautifulSoup
from utils.payloads import SQL_PAYLOADS

logger = logging.getLogger(__name__)

SQL_ERROR_PATTERNS = [
    r"sql syntax", r"mysql_fetch", r"mysql_num_rows",
    r"ora-\d{5}", r"oracle error", r"microsoft ole db",
    r"odbc.*error", r"sqlite.*error", r"pg_query\(\)",
    r"postgresql.*error", r"warning.*mysql",
    r"unclosed quotation", r"quoted string not properly terminated",
    r"syntax error.*sql", r"you have an error in your sql",
    r"supplied argument is not a valid mysql",
    r"invalid query", r"sql command not properly ended",
    r"db2 sql error", r"com\.mysql\.jdbc",
    r"org\.postgresql", r"system\.data\.sqlclient",
    r"\[microsoft\]\[odbc", r"mssql_query\(\)",
    r"sqlstate", r"division by zero",
    r"column.*does not exist", r"table.*doesn't exist",
]


def detect_sqli(url: str, request_manager) -> List[Dict[str, Any]]:
    vulns = []
    vulns.extend(_test_url_params(url, request_manager))
    vulns.extend(_test_forms(url, request_manager))
    return vulns


def _test_url_params(url: str, request_manager) -> List[Dict[str, Any]]:
    vulns = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return vulns

    baseline = request_manager.get(url)
    baseline_text = baseline.text if baseline else ""

    for param_name in params:
        for payload in SQL_PAYLOADS[:8]:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            test_url = (
                f"{parsed.scheme}://{parsed.netloc}"
                f"{parsed.path}?{urlencode(test_params)}"
            )
            try:
                resp = request_manager.get(test_url)
                if not resp:
                    continue

                if _has_sql_error(resp.text):
                    vulns.append({
                        "type": "SQLi",
                        "subtype": "Error-based SQL Injection",
                        "url": url,
                        "parameter": param_name,
                        "payload": payload,
                        "method": "GET",
                        "evidence": "Database error message in response",
                        "description": (
                            f"SQL injection in parameter '{param_name}'. "
                            "Raw database errors confirm unsanitized input reaches the SQL engine."
                        ),
                        "remediation": (
                            "Use parameterized queries. "
                            "Disable verbose DB errors in production."
                        ),
                    })
                    break

                if _is_boolean_injection(param_name, params, parsed, baseline_text, request_manager):
                    vulns.append({
                        "type": "SQLi",
                        "subtype": "Boolean-based SQL Injection",
                        "url": url,
                        "parameter": param_name,
                        "payload": payload,
                        "method": "GET",
                        "evidence": "Response differs between true/false SQL conditions",
                        "description": (
                            f"Boolean SQLi in parameter '{param_name}'. "
                            "Response content varies based on injected SQL conditions."
                        ),
                        "remediation": "Parameterize all queries. Apply WAF rules.",
                    })
                    break
            except Exception as e:
                logger.debug(f"SQLi param error [{url}]: {e}")

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
                if name and itype not in ("submit", "button", "reset", "file"):
                    form_data[name] = "1"
            if not form_data:
                continue

            for field in form_data:
                for payload in SQL_PAYLOADS[:5]:
                    test_data = {**form_data, field: payload}
                    try:
                        if method == "POST":
                            r = request_manager.post(form_url, data=test_data)
                        else:
                            r = request_manager.get(form_url, params=test_data)
                        if r and _has_sql_error(r.text):
                            vulns.append({
                                "type": "SQLi",
                                "subtype": "Form-based SQL Injection",
                                "url": form_url,
                                "parameter": field,
                                "payload": payload,
                                "method": method,
                                "evidence": "DB error in form response",
                                "description": (
                                    f"SQL injection in form field '{field}'. "
                                    "Database errors leak through form submission."
                                ),
                                "remediation": "Use prepared statements. Validate all form input.",
                            })
                            break
                    except Exception as e:
                        logger.debug(f"Form SQLi error: {e}")
    except Exception as e:
        logger.debug(f"Form extraction error [{url}]: {e}")
    return vulns


def _has_sql_error(text: str) -> bool:
    lower = text.lower()
    return any(re.search(p, lower) for p in SQL_ERROR_PATTERNS)


def _is_boolean_injection(param_name, params, parsed, baseline_text, request_manager) -> bool:
    try:
        true_params = {k: v[0] for k, v in params.items()}
        true_params[param_name] = "1 AND 1=1"
        false_params = {k: v[0] for k, v in params.items()}
        false_params[param_name] = "1 AND 1=2"

        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        tr = request_manager.get(f"{base}?{urlencode(true_params)}")
        fr = request_manager.get(f"{base}?{urlencode(false_params)}")
        if not tr or not fr:
            return False

        diff = abs(len(tr.text) - len(fr.text))
        if diff > 50 and abs(len(tr.text) - len(baseline_text)) < diff:
            return True
    except Exception:
        pass
    return False
