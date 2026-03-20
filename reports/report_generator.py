"""
JSON report generator — V2.
Includes CVSS scores, CWE references, auth status, and remediation priority.
"""

import json
import logging
import os
from datetime import datetime
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def generate_report(
    target_url: str,
    vulnerabilities: List[Dict[str, Any]],
    summary: Dict[str, Any],
    output_dir: str = None,
) -> str:
    """
    Save a structured JSON report to disk and return the file path.
    """
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(__file__), "..", "scan_reports")

    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe = (
        target_url.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "_")
        .replace(".", "_")[:40]
    )
    filepath = os.path.join(output_dir, f"scan_v2_{safe}_{timestamp}.json")
    report = _build_report(target_url, vulnerabilities, summary, timestamp)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    logger.info(f"Report saved: {filepath}")
    return filepath


def report_to_json_string(
    target_url: str,
    vulnerabilities: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> str:
    """Return the full report as a JSON string (no file write)."""
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report = _build_report(target_url, vulnerabilities, summary, timestamp)
    return json.dumps(report, indent=2, ensure_ascii=False)


def _build_report(
    target_url: str,
    vulnerabilities: List[Dict[str, Any]],
    summary: Dict[str, Any],
    timestamp: str,
) -> Dict[str, Any]:
    return {
        "report_metadata": {
            "tool": "AI Web Vulnerability Scanner V2",
            "version": "2.0.0",
            "generated_at": timestamp,
            "target": target_url,
            "total_findings": len(vulnerabilities),
            "authenticated_scan": summary.get("authenticated", False),
            "auth_note": summary.get("auth_message", ""),
        },
        "executive_summary": {
            "overall_risk": _overall_risk(summary),
            "total_vulnerabilities": summary.get("total_vulnerabilities", 0),
            "pages_scanned": summary.get("pages_scanned", 0),
            "requests_made": summary.get("requests_made", 0),
            "scan_duration_seconds": summary.get("scan_duration_seconds", 0),
            "severity_breakdown": summary.get("severity_breakdown", {}),
            "type_breakdown": summary.get("type_breakdown", {}),
        },
        "vulnerabilities": [
            _format_vuln(i + 1, v) for i, v in enumerate(vulnerabilities)
        ],
        "remediation_priority": _priority_list(vulnerabilities),
        "cwe_summary": _cwe_summary(vulnerabilities),
    }


def _format_vuln(index: int, v: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": f"VULN-{index:04d}",
        "type": v.get("type", ""),
        "subtype": v.get("subtype", ""),
        "severity": v.get("severity", ""),
        "severity_score": v.get("severity_score", 0),
        "cvss_score": v.get("cvss_score", 0.0),
        "cwe_id": v.get("cwe_id", ""),
        "cwe_description": v.get("cwe_description", ""),
        "url": v.get("url", ""),
        "parameter": v.get("parameter", ""),
        "http_method": v.get("method", ""),
        "payload_used": v.get("payload", ""),
        "evidence": v.get("evidence", ""),
        "confidence": v.get("confidence", ""),
        "description": v.get("description", ""),
        "remediation": v.get("remediation", ""),
        # V2 extras
        "injected_at": v.get("injected_at", ""),
        "test_url": v.get("test_url", ""),
    }


def _overall_risk(summary: Dict[str, Any]) -> str:
    bd = summary.get("severity_breakdown", {})
    if bd.get("Critical", 0) > 0:   return "CRITICAL"
    if bd.get("High", 0) > 0:       return "HIGH"
    if bd.get("Medium", 0) > 0:     return "MEDIUM"
    if bd.get("Low", 0) > 0:        return "LOW"
    return "CLEAN"


def _priority_list(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict] = {}
    for v in vulnerabilities:
        vtype = v.get("type", "Unknown")
        sev = v.get("severity", "Low")
        if vtype not in seen or _rank(sev) > _rank(seen[vtype]["severity"]):
            seen[vtype] = {
                "vulnerability_type": vtype,
                "severity": sev,
                "cvss_score": v.get("cvss_score", 0.0),
                "cwe_id": v.get("cwe_id", ""),
                "count": 0,
                "remediation": v.get("remediation", ""),
            }
        seen[vtype]["count"] += 1

    return sorted(seen.values(), key=lambda x: _rank(x["severity"]), reverse=True)


def _cwe_summary(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Aggregate findings by CWE for the report footer."""
    cwe_map: Dict[str, Dict] = {}
    for v in vulnerabilities:
        cwe = v.get("cwe_id", "")
        if not cwe:
            continue
        if cwe not in cwe_map:
            cwe_map[cwe] = {
                "cwe_id": cwe,
                "description": v.get("cwe_description", ""),
                "count": 0,
                "max_cvss": 0.0,
            }
        cwe_map[cwe]["count"] += 1
        cwe_map[cwe]["max_cvss"] = max(cwe_map[cwe]["max_cvss"], v.get("cvss_score", 0.0))

    return sorted(cwe_map.values(), key=lambda x: x["max_cvss"], reverse=True)


def _rank(severity: str) -> int:
    return {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(severity, 0)
