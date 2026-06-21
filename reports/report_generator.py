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
    recon_data: Dict[str, Any] = None,
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
    report = _build_report(target_url, vulnerabilities, summary, timestamp, recon_data)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    logger.info(f"Report saved: {filepath}")
    return filepath


def report_to_json_string(
    target_url: str,
    vulnerabilities: List[Dict[str, Any]],
    summary: Dict[str, Any],
    recon_data: Dict[str, Any] = None,
) -> str:
    """Return the full report as a JSON string (no file write)."""
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report = _build_report(target_url, vulnerabilities, summary, timestamp, recon_data)
    return json.dumps(report, indent=2, ensure_ascii=False)


def _build_report(
    target_url: str,
    vulnerabilities: List[Dict[str, Any]],
    summary: Dict[str, Any],
    timestamp: str,
    recon_data: Dict[str, Any] = None,
) -> Dict[str, Any]:
    report = {
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
    if recon_data:
        report["reconnaissance"] = _format_recon(recon_data)
    return report


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


def _format_recon(recon: Dict[str, Any]) -> Dict[str, Any]:
    """Format recon_data for the JSON report reconnaissance section."""
    return {
        "target_intelligence": {
            "target_domain": recon.get("target_domain", ""),
            "primary_ip": recon.get("primary_ip"),
            "resolved_ips": recon.get("resolved_ips", []),
            "ipv6_addresses": recon.get("ipv6_addresses", []),
            "ptr_record": recon.get("ptr_record"),
            "asn_number": recon.get("asn_number"),
            "asn_org": recon.get("asn_org"),
            "hosting_country": recon.get("hosting_country"),
        },
        "cdn_detection": {
            "is_behind_cdn": recon.get("is_behind_cdn", False),
            "cdn_provider": recon.get("cdn_provider"),
            "cdn_evidence": recon.get("cdn_evidence"),
            "cdn_bypass_possible": recon.get("cdn_bypass_possible", False),
            "most_likely_origin_ip": recon.get("most_likely_origin_ip"),
            "origin_discovery_method": recon.get("origin_discovery_method"),
            "cdn_bypass_note": recon.get("cdn_bypass_note"),
        },
        "origin_ip_candidates": recon.get("origin_ip_candidates", []),
        "ssl_cert_domains": recon.get("ssl_cert_domains", []),
        "dns_records": {
            "mx_records": recon.get("mx_records", []),
            "ns_records": recon.get("ns_records", []),
            "spf_ip_ranges": recon.get("spf_ip_ranges", []),
        },
        "internal_ip_exposure": {
            "internal_ips_found": recon.get("internal_ips_found", 0),
            "internal_ip_locations": recon.get("internal_ip_locations", []),
        },
    }


def _rank(severity: str) -> int:
    return {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(severity, 0)
