"""
CSV exporter for AI Vulnerability Scanner V2.

Produces a 14-column CSV with proper quoting so that payloads containing
commas, quotes, or multi-line content are handled safely.  The byte output
includes a UTF-8 BOM for seamless import into Microsoft Excel.
"""

import csv
import io
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Column order — mirrors the formatted output from report_generator._format_vuln
CSV_COLUMNS: List[str] = [
    "ID",
    "Type",
    "Subtype",
    "Severity",
    "CVSS",
    "CWE_ID",
    "URL",
    "Parameter",
    "HTTP_Method",
    "Payload",
    "Evidence",
    "Confidence",
    "Description",
    "Remediation",
]


def _is_empty_row(row: Dict[str, Any]) -> bool:
    """Return True if every meaningful field is blank / falsy."""
    # ID is always generated, so skip it when deciding emptiness
    skip = {"ID"}
    return all(
        not str(row.get(col, "")).strip()
        for col in CSV_COLUMNS
        if col not in skip
    )


def _sanitize(value: Any) -> str:
    """Coerce a value to a clean string safe for CSV embedding.

    * ``None`` → empty string
    * Numeric types preserved as-is
    * Strips surrounding whitespace
    """
    if value is None:
        return ""
    return str(value).strip()


def _vuln_to_row(index: int, vuln: Dict[str, Any]) -> Dict[str, str]:
    """Map a raw vulnerability dict to a CSV row dict keyed by CSV_COLUMNS."""
    return {
        "ID": f"VULN-{index:04d}",
        "Type": _sanitize(vuln.get("type")),
        "Subtype": _sanitize(vuln.get("subtype")),
        "Severity": _sanitize(vuln.get("severity")),
        "CVSS": _sanitize(vuln.get("cvss_score", "")),
        "CWE_ID": _sanitize(vuln.get("cwe_id")),
        "URL": _sanitize(vuln.get("url")),
        "Parameter": _sanitize(vuln.get("parameter")),
        "HTTP_Method": _sanitize(vuln.get("method")),
        "Payload": _sanitize(vuln.get("payload")),
        "Evidence": _sanitize(vuln.get("evidence")),
        "Confidence": _sanitize(vuln.get("confidence")),
        "Description": _sanitize(vuln.get("description")),
        "Remediation": _sanitize(vuln.get("remediation")),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_csv(vulnerabilities: list) -> str:
    """
    Generate a CSV string from a list of vulnerability dicts.

    Args:
        vulnerabilities: List of vulnerability dicts as produced by the
            scanner modules (keys: type, subtype, severity, cvss_score,
            cwe_id, url, parameter, method, payload, evidence, confidence,
            description, remediation, …).

    Returns:
        A UTF-8 CSV string with a header row followed by one row per
        vulnerability.  Entries where every data field is empty are
        silently skipped.
    """
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=CSV_COLUMNS,
        quoting=csv.QUOTE_ALL,
        extrasaction="ignore",
    )
    writer.writeheader()

    written = 0
    for idx, vuln in enumerate(vulnerabilities, start=1):
        row = _vuln_to_row(idx, vuln)
        if _is_empty_row(row):
            logger.debug("Skipping empty vulnerability entry at index %d", idx)
            continue
        writer.writerow(row)
        written += 1

    logger.info("Generated CSV report with %d data rows", written)
    return buf.getvalue()


def generate_csv_bytes(vulnerabilities: list) -> bytes:
    """
    Generate CSV output as bytes with a UTF-8 BOM prefix.

    The BOM (``\\xEF\\xBB\\xBF``) ensures Microsoft Excel auto-detects the
    file as UTF-8, avoiding mojibake for non-ASCII payloads and evidence
    strings.

    Args:
        vulnerabilities: Same as :func:`generate_csv`.

    Returns:
        ``bytes`` ready to be written to a file or returned in an HTTP
        response with ``Content-Type: text/csv; charset=utf-8``.
    """
    csv_string = generate_csv(vulnerabilities)
    # UTF-8 BOM + encoded content
    return b"\xef\xbb\xbf" + csv_string.encode("utf-8")
