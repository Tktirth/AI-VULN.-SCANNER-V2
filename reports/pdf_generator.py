"""
PDF report generator for AI Web Vulnerability Scanner V2.

Produces a branded, multi-page security report containing:
  - Cover page with risk badge
  - Executive summary with severity bar chart
  - OWASP Top 10 mapping table
  - Detailed per-finding sections
  - Page-numbered footer

Uses fpdf2 (https://py-pdf.github.io/fpdf2/).
"""

import io
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from fpdf import FPDF

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCANNER_NAME = "AI Web Vulnerability Scanner"
SCANNER_VERSION = "2.0.0"

# RGB tuples keyed by severity / risk rating
SEVERITY_COLORS: Dict[str, tuple] = {
    "CRITICAL": (220, 38, 38),    # red-600
    "HIGH":     (234, 88, 12),    # orange-600
    "MEDIUM":   (202, 138, 4),    # yellow-600
    "LOW":      (22, 163, 74),    # green-600
    "CLEAN":    (156, 163, 175),  # grey-400
    # Also accept title-case keys produced by the scanner
    "Critical": (220, 38, 38),
    "High":     (234, 88, 12),
    "Medium":   (202, 138, 4),
    "Low":      (22, 163, 74),
    "Info":     (156, 163, 175),
}

OWASP_TOP_10: List[Dict[str, str]] = [
    {"id": "A01", "name": "Broken Access Control"},
    {"id": "A02", "name": "Cryptographic Failures"},
    {"id": "A03", "name": "Injection"},
    {"id": "A04", "name": "Insecure Design"},
    {"id": "A05", "name": "Security Misconfiguration"},
    {"id": "A06", "name": "Vulnerable Components"},
    {"id": "A07", "name": "Auth Failures"},
    {"id": "A08", "name": "Software/Data Integrity"},
    {"id": "A09", "name": "Logging Failures"},
    {"id": "A10", "name": "SSRF"},
]

# Mapping from vulnerability *type* keywords → OWASP category id.
# Extend this dict as new scanner modules are added.
_VULN_TYPE_TO_OWASP: Dict[str, str] = {
    # A01 – Broken Access Control
    "idor": "A01", "access_control": "A01", "broken_access": "A01",
    "privilege_escalation": "A01", "path_traversal": "A01",
    "directory_traversal": "A01", "forced_browsing": "A01",
    # A02 – Cryptographic Failures
    "ssl": "A02", "tls": "A02", "crypto": "A02", "certificate": "A02",
    "weak_cipher": "A02", "cleartext": "A02", "http_only": "A02",
    "missing_hsts": "A02",
    # A03 – Injection
    "xss": "A03", "sqli": "A03", "sql_injection": "A03",
    "command_injection": "A03", "cmd_injection": "A03",
    "ssti": "A03", "injection": "A03", "ldap_injection": "A03",
    "xpath_injection": "A03", "nosql_injection": "A03",
    "header_injection": "A03", "crlf_injection": "A03",
    # A04 – Insecure Design
    "insecure_design": "A04", "business_logic": "A04",
    "race_condition": "A04",
    # A05 – Security Misconfiguration
    "misconfig": "A05", "misconfiguration": "A05", "cors": "A05",
    "security_header": "A05", "missing_header": "A05",
    "information_disclosure": "A05", "info_disclosure": "A05",
    "default_credentials": "A05", "directory_listing": "A05",
    "debug_mode": "A05", "verbose_error": "A05",
    "server_info": "A05",
    # A06 – Vulnerable Components
    "outdated": "A06", "vulnerable_component": "A06", "cve": "A06",
    "outdated_software": "A06", "known_vulnerability": "A06",
    # A07 – Auth Failures
    "auth": "A07", "authentication": "A07", "brute_force": "A07",
    "session": "A07", "weak_password": "A07", "csrf": "A07",
    "session_fixation": "A07", "jwt": "A07",
    # A08 – Software/Data Integrity
    "integrity": "A08", "deserialization": "A08", "supply_chain": "A08",
    "subresource": "A08", "sri": "A08",
    # A09 – Logging Failures
    "logging": "A09", "log": "A09", "monitoring": "A09",
    # A10 – SSRF
    "ssrf": "A10", "server_side_request": "A10",
}


# ---------------------------------------------------------------------------
# OWASP mapping helper
# ---------------------------------------------------------------------------

def _map_vuln_to_owasp(vuln_type: str) -> Optional[str]:
    """Return OWASP category id (e.g. 'A03') for a vulnerability type string."""
    vtype = vuln_type.lower().strip()
    # Direct match
    if vtype in _VULN_TYPE_TO_OWASP:
        return _VULN_TYPE_TO_OWASP[vtype]
    # Substring / keyword match
    for keyword, owasp_id in _VULN_TYPE_TO_OWASP.items():
        if keyword in vtype:
            return owasp_id
    return None


def _build_owasp_findings(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
    """Group vulnerability dicts by OWASP category id."""
    grouped: Dict[str, List[Dict]] = {cat["id"]: [] for cat in OWASP_TOP_10}
    for v in vulnerabilities:
        owasp_id = _map_vuln_to_owasp(v.get("type", ""))
        if owasp_id and owasp_id in grouped:
            grouped[owasp_id].append(v)
    return grouped


# ---------------------------------------------------------------------------
# Risk helpers (mirrored from report_generator.py)
# ---------------------------------------------------------------------------

def _overall_risk(summary: Dict[str, Any]) -> str:
    bd = summary.get("severity_breakdown", {})
    if bd.get("Critical", 0) > 0:
        return "CRITICAL"
    if bd.get("High", 0) > 0:
        return "HIGH"
    if bd.get("Medium", 0) > 0:
        return "MEDIUM"
    if bd.get("Low", 0) > 0:
        return "LOW"
    return "CLEAN"


# ---------------------------------------------------------------------------
# Custom FPDF subclass with branded footer
# ---------------------------------------------------------------------------

class _ScanReportPDF(FPDF):
    """FPDF subclass that adds page numbers in the footer."""

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(130, 130, 130)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    # Convenience: safe multi-cell that handles encoding edge-cases
    def safe_cell(self, w, h, txt, **kwargs):
        """Write a cell, replacing characters that latin-1 cannot encode."""
        self.cell(w, h, _sanitize(txt), **kwargs)

    def safe_multi_cell(self, w, h, txt, **kwargs):
        self.multi_cell(w, h, _sanitize(txt), **kwargs)


def _sanitize(text: str) -> str:
    """Replace characters outside latin-1 with '?' to avoid fpdf2 errors."""
    if not text:
        return ""
    return text.encode("latin-1", errors="replace").decode("latin-1")


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def _render_cover(
    pdf: _ScanReportPDF,
    target_url: str,
    org_name: str,
    scan_date_str: str,
    risk: str,
):
    """Page 1: branded cover page."""
    pdf.add_page()

    # Title block
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(30, 30, 30)
    pdf.ln(40)
    pdf.safe_cell(0, 14, "Security Scan Report", align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(6)
    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(80, 80, 80)
    pdf.safe_cell(0, 8, f"{SCANNER_NAME} v{SCANNER_VERSION}", align="C", new_x="LMARGIN", new_y="NEXT")

    # Horizontal rule
    pdf.ln(10)
    pdf.set_draw_color(200, 200, 200)
    pdf.set_line_width(0.5)
    pdf.line(30, pdf.get_y(), pdf.w - 30, pdf.get_y())
    pdf.ln(10)

    # Organisation
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(30, 30, 30)
    pdf.safe_cell(0, 10, f"Organisation:  {org_name}", align="C", new_x="LMARGIN", new_y="NEXT")

    # Target URL
    pdf.set_font("Helvetica", "", 13)
    pdf.set_text_color(60, 60, 60)
    pdf.ln(4)
    pdf.safe_cell(0, 10, f"Target:  {target_url}", align="C", new_x="LMARGIN", new_y="NEXT")

    # Scan date – try to format nicely
    display_date = _format_date(scan_date_str)
    pdf.ln(2)
    pdf.safe_cell(0, 10, f"Scan Date:  {display_date}", align="C", new_x="LMARGIN", new_y="NEXT")

    # Risk badge
    pdf.ln(16)
    _draw_risk_badge(pdf, risk)


def _format_date(raw: str) -> str:
    """Best-effort pretty-print of the scan date."""
    for fmt in ("%Y%m%d_%H%M%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(raw, fmt).strftime("%d %B %Y, %H:%M UTC")
        except ValueError:
            continue
    return raw  # fallback – return as-is


def _draw_risk_badge(pdf: _ScanReportPDF, risk: str):
    """Centered rounded-rect badge with risk label."""
    color = SEVERITY_COLORS.get(risk, (156, 163, 175))
    label = f"Overall Risk: {risk}"

    pdf.set_font("Helvetica", "B", 18)
    label_w = pdf.get_string_width(label) + 24
    badge_h = 14
    x = (pdf.w - label_w) / 2
    y = pdf.get_y()

    # Badge background
    pdf.set_fill_color(*color)
    pdf.rect(x, y, label_w, badge_h, style="F")

    # Badge text (white)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(x, y)
    pdf.cell(label_w, badge_h, label, align="C")

    pdf.ln(badge_h + 4)
    pdf.set_text_color(0, 0, 0)  # reset


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------

def _render_executive_summary(
    pdf: _ScanReportPDF,
    summary: Dict[str, Any],
    risk: str,
):
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(30, 30, 30)
    pdf.safe_cell(0, 12, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    total = summary.get("total_vulnerabilities", 0)
    pages = summary.get("pages_scanned", 0)
    duration = summary.get("scan_duration_seconds", 0)
    breakdown = summary.get("severity_breakdown", {})

    # Key metrics row
    pdf.set_font("Helvetica", "", 12)
    pdf.safe_cell(0, 8, f"Total Vulnerabilities:  {total}", new_x="LMARGIN", new_y="NEXT")
    pdf.safe_cell(0, 8, f"Pages Scanned:  {pages}", new_x="LMARGIN", new_y="NEXT")
    if duration:
        pdf.safe_cell(0, 8, f"Scan Duration:  {duration:.1f}s", new_x="LMARGIN", new_y="NEXT")
    pdf.safe_cell(0, 8, f"Overall Risk Rating:  {risk}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # Severity breakdown bar
    _render_severity_bar(pdf, breakdown, total)


def _render_severity_bar(
    pdf: _ScanReportPDF,
    breakdown: Dict[str, int],
    total: int,
):
    """Horizontal stacked bar showing severity distribution."""
    pdf.set_font("Helvetica", "B", 12)
    pdf.safe_cell(0, 10, "Severity Breakdown", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    bar_x = pdf.l_margin
    bar_y = pdf.get_y()
    bar_w = pdf.w - pdf.l_margin - pdf.r_margin
    bar_h = 12

    if total == 0:
        pdf.set_fill_color(220, 220, 220)
        pdf.rect(bar_x, bar_y, bar_w, bar_h, style="F")
        pdf.set_xy(bar_x, bar_y)
        pdf.set_font("Helvetica", "I", 10)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(bar_w, bar_h, "No vulnerabilities found", align="C")
        pdf.ln(bar_h + 6)
        pdf.set_text_color(0, 0, 0)
        return

    order = ["Critical", "High", "Medium", "Low"]
    cx = bar_x
    for sev in order:
        count = breakdown.get(sev, 0)
        if count == 0:
            continue
        seg_w = (count / total) * bar_w
        color = SEVERITY_COLORS.get(sev, (180, 180, 180))
        pdf.set_fill_color(*color)
        pdf.rect(cx, bar_y, seg_w, bar_h, style="F")

        # Label inside segment
        pdf.set_xy(cx, bar_y)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(255, 255, 255)
        label = f"{sev}: {count}"
        if seg_w > pdf.get_string_width(label) + 4:
            pdf.cell(seg_w, bar_h, label, align="C")
        cx += seg_w

    pdf.ln(bar_h + 4)
    pdf.set_text_color(0, 0, 0)

    # Legend row beneath bar
    pdf.set_font("Helvetica", "", 9)
    for sev in order:
        count = breakdown.get(sev, 0)
        color = SEVERITY_COLORS.get(sev, (180, 180, 180))
        pdf.set_fill_color(*color)
        pdf.rect(pdf.get_x(), pdf.get_y() + 1, 4, 4, style="F")
        pdf.set_x(pdf.get_x() + 6)
        pdf.safe_cell(30, 6, f"{sev}: {count}")
        pdf.set_x(pdf.get_x() + 4)
    pdf.ln(10)


# ---------------------------------------------------------------------------
# OWASP Top 10 table
# ---------------------------------------------------------------------------

def _render_owasp_table(
    pdf: _ScanReportPDF,
    vulnerabilities: List[Dict[str, Any]],
):
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(30, 30, 30)
    pdf.safe_cell(0, 12, "OWASP Top 10 Coverage", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    owasp_findings = _build_owasp_findings(vulnerabilities)

    col_id_w = 18
    col_name_w = 70
    col_status_w = 30
    col_count_w = 22
    col_sev_w = pdf.w - pdf.l_margin - pdf.r_margin - col_id_w - col_name_w - col_status_w - col_count_w
    row_h = 8

    # Header row
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(40, 40, 40)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(col_id_w, row_h, "ID", border=1, fill=True, align="C")
    pdf.cell(col_name_w, row_h, "Category", border=1, fill=True)
    pdf.cell(col_status_w, row_h, "Status", border=1, fill=True, align="C")
    pdf.cell(col_count_w, row_h, "Findings", border=1, fill=True, align="C")
    pdf.cell(col_sev_w, row_h, "Highest Severity", border=1, fill=True, align="C")
    pdf.ln(row_h)

    pdf.set_font("Helvetica", "", 10)
    for cat in OWASP_TOP_10:
        findings = owasp_findings[cat["id"]]
        pdf.set_text_color(30, 30, 30)
        pdf.cell(col_id_w, row_h, cat["id"], border=1, align="C")
        pdf.cell(col_name_w, row_h, cat["name"], border=1)

        if findings:
            count = len(findings)
            max_sev = _highest_severity(findings)
            color = SEVERITY_COLORS.get(max_sev, (60, 60, 60))

            # Status
            pdf.set_text_color(*color)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(col_status_w, row_h, "FOUND", border=1, align="C")
            # Count
            pdf.set_text_color(30, 30, 30)
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(col_count_w, row_h, str(count), border=1, align="C")
            # Highest severity
            pdf.set_text_color(*color)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(col_sev_w, row_h, max_sev, border=1, align="C")
        else:
            pdf.set_text_color(160, 160, 160)
            pdf.set_font("Helvetica", "I", 10)
            pdf.cell(col_status_w, row_h, "NOT TESTED", border=1, align="C")
            pdf.cell(col_count_w, row_h, "-", border=1, align="C")
            pdf.cell(col_sev_w, row_h, "-", border=1, align="C")

        pdf.ln(row_h)

    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "", 10)


def _highest_severity(findings: List[Dict[str, Any]]) -> str:
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    best, best_rank = "Low", 0
    for f in findings:
        sev = f.get("severity", "Low")
        rank = order.get(sev, 0)
        if rank > best_rank:
            best, best_rank = sev, rank
    return best


# ---------------------------------------------------------------------------
# Finding details
# ---------------------------------------------------------------------------

_PAYLOAD_MAX_LEN = 200


def _render_findings(
    pdf: _ScanReportPDF,
    vulnerabilities: List[Dict[str, Any]],
):
    if not vulnerabilities:
        return

    pdf.add_page()
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(30, 30, 30)
    pdf.safe_cell(0, 12, "Detailed Findings", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    for idx, vuln in enumerate(vulnerabilities, start=1):
        _render_single_finding(pdf, idx, vuln)


def _render_single_finding(
    pdf: _ScanReportPDF,
    index: int,
    vuln: Dict[str, Any],
):
    """Render one finding; adds a new page if space is low."""
    # Check remaining space – each finding needs ~60mm minimum
    if pdf.get_y() > pdf.h - 70:
        pdf.add_page()

    sev = vuln.get("severity", "Low")
    sev_color = SEVERITY_COLORS.get(sev, (60, 60, 60))
    vtype = vuln.get("type", "Unknown")

    # Section header
    pdf.set_draw_color(200, 200, 200)
    pdf.set_line_width(0.3)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(3)

    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(30, 30, 30)
    pdf.safe_cell(0, 8, f"VULN-{index:04d}:  {vtype}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)

    label_w = 38
    value_w = pdf.w - pdf.l_margin - pdf.r_margin - label_w

    # Severity (colored)
    _finding_row(pdf, "Severity:", sev, label_w, value_w, text_color=sev_color, bold_value=True)
    # URL
    _finding_row(pdf, "URL:", vuln.get("url", "-"), label_w, value_w)
    # Parameter
    _finding_row(pdf, "Parameter:", vuln.get("parameter", "-") or "-", label_w, value_w)
    # Payload (truncated)
    payload = vuln.get("payload", "") or ""
    if len(payload) > _PAYLOAD_MAX_LEN:
        payload = payload[:_PAYLOAD_MAX_LEN] + "..."
    _finding_row(pdf, "Payload:", payload or "-", label_w, value_w)
    # Evidence
    evidence = vuln.get("evidence", "") or ""
    if evidence:
        _finding_row_multi(pdf, "Evidence:", evidence, label_w, value_w)
    # Remediation
    remediation = vuln.get("remediation", "") or ""
    if remediation:
        _finding_row_multi(pdf, "Remediation:", remediation, label_w, value_w)

    pdf.ln(4)


def _finding_row(
    pdf: _ScanReportPDF,
    label: str,
    value: str,
    label_w: float,
    value_w: float,
    text_color: tuple = (50, 50, 50),
    bold_value: bool = False,
):
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(80, 80, 80)
    pdf.safe_cell(label_w, 7, label)
    pdf.set_font("Helvetica", "B" if bold_value else "", 10)
    pdf.set_text_color(*text_color)
    pdf.safe_cell(value_w, 7, value or "-", new_x="LMARGIN", new_y="NEXT")


def _finding_row_multi(
    pdf: _ScanReportPDF,
    label: str,
    value: str,
    label_w: float,
    value_w: float,
):
    """Row whose value may wrap to multiple lines."""
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(80, 80, 80)
    pdf.safe_cell(label_w, 7, label)

    x_after_label = pdf.get_x()
    y_before = pdf.get_y()

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(50, 50, 50)
    pdf.set_x(x_after_label)
    pdf.safe_multi_cell(value_w, 6, value)

    # Ensure we advance past the multi-cell
    if pdf.get_y() <= y_before + 7:
        pdf.set_y(y_before + 7)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_pdf_report(
    target_url: str,
    org_name: str,
    scan_date: str,
    vulnerabilities: list,
    summary: dict,
    output_path: str = None,
) -> bytes:
    """
    Build a professional PDF security scan report.

    Args:
        target_url:      The scanned URL / domain.
        org_name:        Name of the organisation requesting the scan.
        scan_date:       ISO-ish date string for the scan.
        vulnerabilities: List of vulnerability dicts (same schema used by
                         ``report_generator.generate_report``).
        summary:         Summary dict with keys such as ``severity_breakdown``,
                         ``total_vulnerabilities``, ``pages_scanned``, etc.
        output_path:     If provided, the PDF is also written to this path.

    Returns:
        Raw PDF bytes suitable for direct upload (e.g. to GCS).
    """
    risk = _overall_risk(summary)

    pdf = _ScanReportPDF(orientation="P", unit="mm", format="A4")
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)

    # 1. Cover page
    _render_cover(pdf, target_url, org_name, scan_date, risk)

    # 2. Executive summary
    _render_executive_summary(pdf, summary, risk)

    # 3. OWASP Top 10 table
    _render_owasp_table(pdf, vulnerabilities)

    # 4. Finding details
    _render_findings(pdf, vulnerabilities)

    # Produce bytes
    pdf_bytes: bytes = pdf.output()

    # Optionally persist to disk
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "wb") as fh:
            fh.write(pdf_bytes)
        logger.info("PDF report saved: %s", output_path)

    return pdf_bytes
