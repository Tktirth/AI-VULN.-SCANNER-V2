"""
AI-Powered Web Vulnerability Scanner V2 — Streamlit Dashboard
Run: streamlit run app.py
"""

import os
import sys
import logging
from datetime import datetime
from typing import List, Dict, Any

import streamlit as st
import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))

from scanner_engine import ScannerEngineV2
from reports.report_generator import report_to_json_string

logging.basicConfig(level=logging.WARNING)

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI Vuln Scanner V2",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CSS — Dark terminal aesthetic with CVSS color ramp ────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Inter:wght@300;400;500;600;700&display=swap');

  :root {
    --bg:        #09090b;
    --bg2:       #0f1117;
    --bg3:       #16181f;
    --bg4:       #1c1f28;
    --green:     #22d3a5;
    --green-dim: #16a37e;
    --border:    rgba(34,211,165,0.12);
    --border2:   rgba(255,255,255,0.06);
    --text:      #e2e8f0;
    --text-dim:  #64748b;
    --text-muted:#334155;
    --red:       #f43f5e;
    --orange:    #f97316;
    --yellow:    #eab308;
    --blue:      #3b82f6;
    --mono:      'JetBrains Mono', monospace;
    --sans:      'Inter', sans-serif;
  }

  html, body, [data-testid="stAppViewContainer"], .main {
    background: var(--bg) !important;
    color: var(--text) !important;
    font-family: var(--sans) !important;
  }

  [data-testid="stSidebar"] {
    background: var(--bg2) !important;
    border-right: 1px solid var(--border2) !important;
  }
  [data-testid="stSidebar"] * { color: var(--text) !important; }

  /* ── Header ── */
  .v2-header {
    background: linear-gradient(135deg, var(--bg2) 0%, var(--bg3) 100%);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 2rem 2.5rem;
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    gap: 1.5rem;
  }
  .v2-title {
    font-family: var(--mono);
    font-size: 1.7rem;
    font-weight: 700;
    color: var(--green);
    letter-spacing: -0.02em;
    margin: 0;
  }
  .v2-badge {
    background: rgba(34,211,165,0.1);
    border: 1px solid var(--green-dim);
    color: var(--green);
    font-family: var(--mono);
    font-size: 0.68rem;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    letter-spacing: 0.1em;
  }
  .v2-subtitle {
    font-size: 0.82rem;
    color: var(--text-dim);
    margin: 0.25rem 0 0;
  }

  /* ── Section labels ── */
  .section-label {
    font-family: var(--mono);
    font-size: 0.7rem;
    letter-spacing: 0.18em;
    color: var(--text-dim);
    text-transform: uppercase;
    border-bottom: 1px solid var(--border2);
    padding-bottom: 0.5rem;
    margin: 1.5rem 0 1rem;
  }

  /* ── Metric cards ── */
  .metric-row { display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 1rem; }
  .metric-card {
    flex: 1;
    min-width: 100px;
    background: var(--bg3);
    border: 1px solid var(--border2);
    border-radius: 8px;
    padding: 1rem 1.2rem;
    text-align: center;
  }
  .metric-value {
    font-family: var(--mono);
    font-size: 1.9rem;
    font-weight: 700;
    line-height: 1;
  }
  .metric-label {
    font-size: 0.68rem;
    color: var(--text-dim);
    letter-spacing: 0.12em;
    text-transform: uppercase;
    margin-top: 0.35rem;
  }

  /* ── Severity / CVSS colors ── */
  .sev-critical { color: var(--red) !important; }
  .sev-high     { color: var(--orange) !important; }
  .sev-medium   { color: var(--yellow) !important; }
  .sev-low      { color: var(--green) !important; }

  .badge {
    display: inline-block;
    padding: 0.18rem 0.6rem;
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }
  .badge-critical { background:rgba(244,63,94,0.15);  color:#f43f5e; border:1px solid #f43f5e; }
  .badge-high     { background:rgba(249,115,22,0.12); color:#f97316; border:1px solid #f97316; }
  .badge-medium   { background:rgba(234,179,8,0.12);  color:#eab308; border:1px solid #eab308; }
  .badge-low      { background:rgba(34,211,165,0.1);  color:#22d3a5; border:1px solid #22d3a5; }

  .cvss-pill {
    display: inline-block;
    padding: 0.15rem 0.55rem;
    border-radius: 3px;
    font-family: var(--mono);
    font-size: 0.72rem;
    font-weight: 700;
    background: var(--bg4);
    border: 1px solid var(--border2);
    color: var(--text);
  }
  .cwe-tag {
    display: inline-block;
    padding: 0.12rem 0.5rem;
    border-radius: 3px;
    font-family: var(--mono);
    font-size: 0.68rem;
    background: rgba(59,130,246,0.1);
    border: 1px solid rgba(59,130,246,0.3);
    color: var(--blue);
  }

  /* ── Vuln cards ── */
  .vuln-card {
    background: var(--bg3);
    border: 1px solid var(--border2);
    border-left: 3px solid var(--border2);
    border-radius: 8px;
    padding: 1rem 1.2rem 0.9rem;
    margin-bottom: 0.6rem;
    transition: border-color 0.15s;
  }
  .vuln-card:hover      { border-left-color: var(--green-dim); }
  .vuln-card.critical   { border-left-color: var(--red); }
  .vuln-card.high       { border-left-color: var(--orange); }
  .vuln-card.medium     { border-left-color: var(--yellow); }
  .vuln-card.low        { border-left-color: var(--green); }

  .vuln-type   { font-family: var(--mono); font-size: 0.88rem; font-weight: 600; color: var(--text); }
  .vuln-sub    { font-family: var(--mono); font-size: 0.75rem; color: var(--text-dim); }
  .vuln-url    { font-family: var(--mono); font-size: 0.72rem; color: var(--text-dim); margin-top: 0.3rem; word-break:break-all; }
  .vuln-desc   { font-size: 0.83rem; color: var(--text); margin-top: 0.55rem; line-height: 1.55; }
  .vuln-payload {
    font-family: var(--mono);
    font-size: 0.72rem;
    background: var(--bg2);
    border: 1px solid var(--border2);
    border-radius: 4px;
    padding: 0.25rem 0.55rem;
    margin-top: 0.45rem;
    color: var(--orange);
    word-break: break-all;
  }
  .vuln-fix    { font-size: 0.78rem; color: var(--green-dim); margin-top: 0.45rem; }
  .vuln-tags   { display:flex; gap:0.4rem; flex-wrap:wrap; margin-top:0.5rem; align-items:center; }

  /* ── Auth status strip ── */
  .auth-strip {
    padding: 0.55rem 1rem;
    border-radius: 6px;
    font-family: var(--mono);
    font-size: 0.78rem;
    margin-bottom: 1rem;
  }
  .auth-ok   { background:rgba(34,211,165,0.08); border:1px solid var(--green-dim); color:var(--green); }
  .auth-fail { background:rgba(244,63,94,0.08);  border:1px solid var(--red);       color:var(--red);   }
  .auth-none { background:rgba(100,116,139,0.1); border:1px solid var(--border2);   color:var(--text-dim); }

  /* ── Risk banner ── */
  .risk-banner {
    text-align: center;
    padding: 0.7rem;
    border-radius: 6px;
    font-family: var(--mono);
    font-size: 0.82rem;
    font-weight: 700;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    margin-bottom: 1.2rem;
  }
  .risk-CRITICAL { background:rgba(244,63,94,0.12);  border:1px solid var(--red);    color:var(--red); }
  .risk-HIGH     { background:rgba(249,115,22,0.1);  border:1px solid var(--orange); color:var(--orange); }
  .risk-MEDIUM   { background:rgba(234,179,8,0.1);   border:1px solid var(--yellow); color:var(--yellow); }
  .risk-LOW      { background:rgba(34,211,165,0.08); border:1px solid var(--green);  color:var(--green); }
  .risk-CLEAN    { background:rgba(34,211,165,0.08); border:1px solid var(--green);  color:var(--green); }

  /* ── Terminal ── */
  .terminal {
    background: var(--bg2);
    border: 1px solid var(--border2);
    border-radius: 6px;
    padding: 0.9rem 1rem;
    font-family: var(--mono);
    font-size: 0.73rem;
    color: var(--green-dim);
    max-height: 180px;
    overflow-y: auto;
    line-height: 1.65;
  }
  .tline::before { content: '❯ '; opacity: 0.5; }

  /* ── Inputs ── */
  .stTextInput input, .stSelectbox select {
    background: var(--bg3) !important;
    border: 1px solid var(--border2) !important;
    border-radius: 6px !important;
    color: var(--text) !important;
    font-family: var(--mono) !important;
    font-size: 0.85rem !important;
  }
  .stTextInput input:focus {
    border-color: var(--green-dim) !important;
    box-shadow: 0 0 0 1px var(--green-dim) !important;
  }

  /* ── Button ── */
  .stButton > button {
    background: rgba(34,211,165,0.08) !important;
    border: 1px solid var(--green-dim) !important;
    color: var(--green) !important;
    font-family: var(--mono) !important;
    font-size: 0.82rem !important;
    letter-spacing: 0.08em !important;
    border-radius: 6px !important;
    padding: 0.5rem 1.5rem !important;
    transition: all 0.15s !important;
  }
  .stButton > button:hover {
    background: rgba(34,211,165,0.15) !important;
    box-shadow: 0 0 16px rgba(34,211,165,0.15) !important;
  }

  /* ── Misc ── */
  .stCheckbox label { color: var(--text) !important; font-size: 0.85rem !important; }
  .stSlider [data-testid="stMarkdownContainer"] p { color: var(--text-dim) !important; font-size: 0.8rem !important; }
  #MainMenu, footer, header { visibility: hidden; }
  ::-webkit-scrollbar { width: 3px; }
  ::-webkit-scrollbar-thumb { background: var(--green-dim); border-radius: 2px; }

  /* ── CVSS bar ── */
  .cvss-bar-bg {
    height: 5px;
    background: var(--bg4);
    border-radius: 3px;
    margin-top: 0.4rem;
    overflow: hidden;
    width: 100%;
  }
  .cvss-bar-fill { height: 100%; border-radius: 3px; transition: width 0.3s; }

  /* ── Landing placeholder ── */
  .landing {
    text-align: center;
    padding: 4rem 0 3rem;
    color: var(--text-muted);
  }
  .landing-icon { font-size: 3.5rem; opacity: 0.25; margin-bottom: 1rem; }
  .landing-text { font-family: var(--mono); font-size: 0.8rem; letter-spacing: 0.18em; }
  .landing-caps { font-size: 0.7rem; opacity: 0.6; margin-top: 0.5rem; }
</style>
""", unsafe_allow_html=True)


# ── Session state ─────────────────────────────────────────────────────────────
def _init():
    defaults = {
        "scanning": False, "done": False,
        "vulnerabilities": [], "summary": {},
        "log_lines": [], "report_json": "",
        "auth_status": {},
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init()

PHASE_LABELS = {
    "auth":       "🔑 Authentication",
    "crawl":      "🌐 Crawling",
    "directories":"📁 Directory Discovery",
    "headers":    "🔒 Header Analysis",
    "xss":        "⚡ XSS Detection",
    "sqli":       "💉 SQL Injection",
    "redirect":   "↪️  Open Redirect",
    "stored_xss": "🕳️  Stored XSS (2-pass)",
    "idor":       "🔓 IDOR Fuzzing",
    "ai":         "🤖 AI CVSS Classification",
}

SEVERITY_COLORS = {"Critical": "#f43f5e", "High": "#f97316", "Medium": "#eab308", "Low": "#22d3a5"}
RISK_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "CLEAN": "✅"}


def badge(severity: str) -> str:
    cls = severity.lower() if severity.lower() in ("critical", "high", "medium", "low") else "low"
    return f'<span class="badge badge-{cls}">{severity}</span>'

def cvss_bar(score: float) -> str:
    pct = min((score / 10.0) * 100, 100)
    if score >= 9.0:   color = "#f43f5e"
    elif score >= 7.0: color = "#f97316"
    elif score >= 4.0: color = "#eab308"
    else:              color = "#22d3a5"
    return (
        f'<div class="cvss-bar-bg">'
        f'<div class="cvss-bar-fill" style="width:{pct:.0f}%;background:{color};"></div>'
        f'</div>'
    )

def render_vuln_card(v: Dict[str, Any]):
    sev = v.get("severity", "Low")
    sev_cls = sev.lower()
    payload = v.get("payload", "N/A")
    cvss = v.get("cvss_score", 0.0)
    cwe = v.get("cwe_id", "")
    cwe_desc = v.get("cwe_description", "")
    confidence = v.get("confidence", "")
    injected_at = v.get("injected_at", "")

    payload_html = (
        f'<div class="vuln-payload">PAYLOAD: {payload}</div>'
        if payload and payload != "N/A" else ""
    )
    injected_html = (
        f'<div class="vuln-url">INJECTED AT: {injected_at}</div>'
        if injected_at else ""
    )
    confidence_html = (
        f'<span style="font-family:var(--mono);font-size:0.68rem;color:{"#22d3a5" if confidence=="Confirmed" else "#eab308"};">'
        f'◉ {confidence}</span>'
        if confidence else ""
    )

    st.markdown(f"""
    <div class="vuln-card {sev_cls}">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:0.5rem;flex-wrap:wrap;">
        <div>
          <span class="vuln-type">{v.get('type','')} </span>
          <span class="vuln-sub">— {v.get('subtype','')}</span>
          <div class="vuln-url">🔗 {v.get('url','')}</div>
          {injected_html}
          {'<div class="vuln-url">PARAM: ' + v.get('parameter','') + '</div>' if v.get('parameter') and v.get('parameter') != 'N/A' else ''}
        </div>
        <div style="display:flex;flex-direction:column;align-items:flex-end;gap:0.35rem;">
          {badge(sev)}
          <span class="cvss-pill">CVSS {cvss}</span>
        </div>
      </div>
      {cvss_bar(cvss)}
      <div class="vuln-tags">
        {'<span class="cwe-tag">' + cwe + '</span>' if cwe else ''}
        {confidence_html}
        {'<span style="font-family:var(--mono);font-size:0.68rem;color:var(--text-dim);">' + cwe_desc[:55] + ('...' if len(cwe_desc)>55 else '') + '</span>' if cwe_desc else ''}
      </div>
      <div class="vuln-desc">{v.get('description','')}</div>
      {payload_html}
      <div class="vuln-fix">🔧 {v.get('remediation','')}</div>
    </div>
    """, unsafe_allow_html=True)


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="section-label">⚙ Scan Modules</div>', unsafe_allow_html=True)
    scan_xss        = st.checkbox("XSS Detection",            value=True)
    scan_stored_xss = st.checkbox("Stored XSS (2-pass)",      value=True)
    scan_sqli       = st.checkbox("SQL Injection",            value=True)
    scan_headers    = st.checkbox("Security Headers",         value=True)
    scan_redirect   = st.checkbox("Open Redirect",            value=True)
    scan_dirs       = st.checkbox("Directory Discovery",      value=True)
    scan_idor       = st.checkbox("IDOR Fuzzing",             value=True)

    st.markdown('<div class="section-label">🔑 Authentication</div>', unsafe_allow_html=True)
    auth_mode = st.selectbox(
        "Auth mode",
        ["none", "form", "cookie", "token"],
        format_func=lambda x: {
            "none":   "None — public scan",
            "form":   "Form Login",
            "cookie": "Cookie Injection",
            "token":  "Bearer / API Token",
        }[x],
    )

    login_url = username = password = logged_in_indicator = ""
    cookies_raw = token = token_scheme = ""

    if auth_mode == "form":
        login_url = st.text_input("Login page URL", placeholder="https://site.com/login")
        username  = st.text_input("Username / Email")
        password  = st.text_input("Password", type="password")
        logged_in_indicator = st.text_input(
            "Logged-in indicator (optional)",
            placeholder="e.g. Dashboard, Welcome back",
            help="A string that appears in the response only when logged in. Used to verify the session.",
        )

    elif auth_mode == "cookie":
        cookies_raw = st.text_area(
            "Cookies (one per line: name=value)",
            placeholder="session=abc123\ncsrftoken=xyz",
            height=90,
        )

    elif auth_mode == "token":
        token        = st.text_input("Token value", type="password")
        token_scheme = st.selectbox("Scheme", ["Bearer", "Token", "Basic", "ApiKey"])

    st.markdown('<div class="section-label">🎛 Tuning</div>', unsafe_allow_html=True)
    max_pages   = st.slider("Max pages to crawl", 5, 60, 20)
    req_delay   = st.slider("Request delay (s)", 0.1, 2.0, 0.3, 0.1)
    req_timeout = st.slider("Timeout (s)", 5, 30, 10)

    st.markdown('<div class="section-label">⚠ Legal</div>', unsafe_allow_html=True)
    st.markdown(
        '<div style="font-size:0.7rem;color:#475569;line-height:1.6;">'
        'Only scan targets you own or have explicit written permission to test. '
        'Unauthorized scanning is illegal.'
        '</div>',
        unsafe_allow_html=True,
    )


# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="v2-header">
  <div>
    <div style="display:flex;align-items:center;gap:0.75rem;">
      <span style="font-size:1.8rem;">🛡️</span>
      <div>
        <div style="display:flex;align-items:center;gap:0.6rem;">
          <p class="v2-title">AI Vulnerability Scanner</p>
          <span class="v2-badge">V2.0</span>
        </div>
        <p class="v2-subtitle">
          Auth · XSS · Stored XSS · SQLi · IDOR · Headers · Redirects · Dirs &nbsp;·&nbsp;
          CVSS Scoring · CWE References
        </p>
      </div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)


# ── URL input + Launch ────────────────────────────────────────────────────────
col_url, col_btn = st.columns([5, 1])
with col_url:
    target_url = st.text_input(
        "target", label_visibility="collapsed",
        placeholder="https://target-site.com",
    )
with col_btn:
    launch = st.button("▶ SCAN", use_container_width=True)


# ── Parse cookies input ───────────────────────────────────────────────────────
def _parse_cookies(raw: str) -> Dict[str, str]:
    result = {}
    for line in raw.strip().splitlines():
        line = line.strip()
        if "=" in line:
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip()
    return result


# ── Trigger scan ──────────────────────────────────────────────────────────────
if launch:
    if not target_url or not target_url.startswith(("http://", "https://")):
        st.error("❌ Enter a valid URL starting with http:// or https://")
    else:
        st.session_state.scanning     = True
        st.session_state.done         = False
        st.session_state.vulnerabilities = []
        st.session_state.summary      = {}
        st.session_state.log_lines    = []
        st.session_state.report_json  = ""
        st.session_state.auth_status  = {}


# ── Scan execution ────────────────────────────────────────────────────────────
if st.session_state.scanning and not st.session_state.done:
    st.markdown('<div class="section-label">📡 Live Progress</div>', unsafe_allow_html=True)
    progress_bar = st.progress(0.0)
    phase_txt    = st.empty()
    terminal     = st.empty()

    def _progress(phase: str, pct: float, msg: str):
        label = PHASE_LABELS.get(phase, phase.upper())
        ts    = datetime.now().strftime("%H:%M:%S")
        st.session_state.log_lines.append(f"[{ts}] {label}: {msg}")
        if len(st.session_state.log_lines) > 50:
            st.session_state.log_lines = st.session_state.log_lines[-50:]

        progress_bar.progress(min(pct, 1.0))
        phase_txt.markdown(
            f'<div style="font-family:var(--mono,monospace);font-size:0.78rem;color:#22d3a5;">'
            f'{label} — {msg[:72]}</div>',
            unsafe_allow_html=True,
        )
        lines_html = "".join(
            f'<div class="tline">{l}</div>'
            for l in st.session_state.log_lines[-16:]
        )
        terminal.markdown(
            f'<div class="terminal">{lines_html}</div>',
            unsafe_allow_html=True,
        )

    with st.spinner("Scanning..."):
        try:
            engine = ScannerEngineV2(
                target_url=target_url,
                auth_mode=auth_mode,
                login_url=login_url,
                username=username,
                password=password,
                cookies=_parse_cookies(cookies_raw) if auth_mode == "cookie" else {},
                token=token,
                token_scheme=token_scheme,
                logged_in_indicator=logged_in_indicator,
                scan_xss=scan_xss,
                scan_stored_xss=scan_stored_xss,
                scan_sqli=scan_sqli,
                scan_headers=scan_headers,
                scan_redirect=scan_redirect,
                scan_directories=scan_dirs,
                scan_idor=scan_idor,
                max_pages=max_pages,
                request_timeout=req_timeout,
                request_delay=req_delay,
            )
            vulns   = engine.run(progress_callback=_progress)
            summary = engine.get_summary()
            engine.close()

            st.session_state.vulnerabilities = vulns
            st.session_state.summary         = summary
            st.session_state.auth_status     = {
                "authenticated": summary.get("authenticated", False),
                "message":       summary.get("auth_message", ""),
            }
            st.session_state.report_json = report_to_json_string(target_url, vulns, summary)
            st.session_state.done        = True
            st.session_state.scanning    = False
            st.rerun()

        except Exception as e:
            st.session_state.scanning = False
            st.error(f"❌ Scan failed: {e}")


# ── Results ───────────────────────────────────────────────────────────────────
if st.session_state.done:
    vulns   = st.session_state.vulnerabilities
    summary = st.session_state.summary
    auth_st = st.session_state.auth_status

    # Auth status strip
    if auth_st:
        if auth_st.get("authenticated"):
            auth_cls, auth_icon = "auth-ok",   "🔑"
        elif auth_mode == "none":
            auth_cls, auth_icon = "auth-none",  "🔓"
        else:
            auth_cls, auth_icon = "auth-fail",  "⚠️"
        st.markdown(
            f'<div class="auth-strip {auth_cls}">'
            f'{auth_icon} {auth_st.get("message","")}'
            f'</div>',
            unsafe_allow_html=True,
        )

    # Risk banner
    bd = summary.get("severity_breakdown", {})
    risk = ("CRITICAL" if bd.get("Critical",0)>0 else
            "HIGH"     if bd.get("High",0)>0     else
            "MEDIUM"   if bd.get("Medium",0)>0   else
            "LOW"      if bd.get("Low",0)>0       else "CLEAN")

    st.markdown(
        f'<div class="risk-banner risk-{risk}">'
        f'{RISK_ICONS.get(risk,"")} OVERALL RISK: {risk}'
        f'</div>',
        unsafe_allow_html=True,
    )

    # Metrics
    st.markdown('<div class="section-label">📊 Metrics</div>', unsafe_allow_html=True)
    cols = st.columns(7)
    metrics = [
        ("TOTAL",     str(summary.get("total_vulnerabilities", 0)), "#22d3a5"),
        ("CRITICAL",  str(bd.get("Critical", 0)),                   "#f43f5e"),
        ("HIGH",      str(bd.get("High", 0)),                       "#f97316"),
        ("MEDIUM",    str(bd.get("Medium", 0)),                     "#eab308"),
        ("LOW",       str(bd.get("Low", 0)),                        "#22d3a5"),
        ("PAGES",     str(summary.get("pages_scanned", 0)),          "#94a3b8"),
        ("TIME",      f"{summary.get('scan_duration_seconds',0)}s",  "#94a3b8"),
    ]
    for col, (label, val, color) in zip(cols, metrics):
        with col:
            st.markdown(
                f'<div class="metric-card">'
                f'<div class="metric-value" style="color:{color};">{val}</div>'
                f'<div class="metric-label">{label}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    st.markdown("<br>", unsafe_allow_html=True)

    if not vulns:
        st.success("✅ No vulnerabilities detected. The target passed all enabled modules.")
    else:
        # Filters
        st.markdown('<div class="section-label">🔍 Findings</div>', unsafe_allow_html=True)
        fc1, fc2, fc3 = st.columns(3)
        with fc1:
            sev_opts  = ["All"] + [s for s in ["Critical","High","Medium","Low"] if bd.get(s,0)>0]
            f_sev     = st.selectbox("Severity", sev_opts)
        with fc2:
            type_opts = ["All"] + sorted({v.get("type","") for v in vulns})
            f_type    = st.selectbox("Type", type_opts)
        with fc3:
            cwe_opts  = ["All"] + sorted({v.get("cwe_id","") for v in vulns if v.get("cwe_id")})
            f_cwe     = st.selectbox("CWE", cwe_opts)

        filtered = vulns
        if f_sev  != "All": filtered = [v for v in filtered if v.get("severity") == f_sev]
        if f_type != "All": filtered = [v for v in filtered if v.get("type") == f_type]
        if f_cwe  != "All": filtered = [v for v in filtered if v.get("cwe_id") == f_cwe]

        st.markdown(
            f'<div style="font-family:monospace;font-size:0.72rem;color:#475569;margin-bottom:0.8rem;">'
            f'Showing {len(filtered)} of {len(vulns)} findings</div>',
            unsafe_allow_html=True,
        )

        for v in filtered:
            render_vuln_card(v)

        # Table view
        st.markdown('<div class="section-label">📋 Table View</div>', unsafe_allow_html=True)
        df = pd.DataFrame([{
            "Severity": v.get("severity",""),
            "CVSS":     v.get("cvss_score",""),
            "CWE":      v.get("cwe_id",""),
            "Type":     v.get("type",""),
            "Subtype":  v.get("subtype",""),
            "URL":      v.get("url","")[:55] + ("..." if len(v.get("url",""))>55 else ""),
            "Parameter":v.get("parameter","")[:28],
            "Method":   v.get("method",""),
            "Confidence": v.get("confidence",""),
        } for v in filtered])
        if not df.empty:
            st.dataframe(df, use_container_width=True, hide_index=True)

        # CVSS breakdown chart
        st.markdown('<div class="section-label">📈 CVSS Distribution</div>', unsafe_allow_html=True)
        if vulns:
            cvss_df = pd.DataFrame({
                "Vulnerability": [f"{v.get('type','')} ({v.get('parameter','')[:15]})" for v in vulns[:20]],
                "CVSS Score":    [v.get("cvss_score", 0.0) for v in vulns[:20]],
            })
            st.bar_chart(cvss_df.set_index("Vulnerability"))

    # Export
    st.markdown('<div class="section-label">📥 Export</div>', unsafe_allow_html=True)
    st.download_button(
        "⬇ Download JSON Report (V2)",
        data=st.session_state.report_json,
        file_name=f"vuln_v2_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json",
    )
    with st.expander("Preview JSON"):
        preview = st.session_state.report_json
        st.code(
            preview[:5000] + ("\n... [truncated]" if len(preview) > 5000 else ""),
            language="json",
        )

elif not st.session_state.scanning:
    st.markdown("""
    <div class="landing">
      <div class="landing-icon">⬡</div>
      <div class="landing-text">ENTER A TARGET URL AND PRESS SCAN</div>
      <div class="landing-caps">
        AUTH · XSS · STORED XSS · SQLi · IDOR · HEADERS · REDIRECT · DIRS · CVSS · CWE
      </div>
    </div>
    """, unsafe_allow_html=True)
