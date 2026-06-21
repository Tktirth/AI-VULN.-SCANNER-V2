<div align="center">

# 🛡️ AI Vulnerability Scanner V2

### Intelligent Web Application Security Assessment Framework

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-22d3a5?style=for-the-badge)](LICENSE)
[![Security Policy](https://img.shields.io/badge/Security-Policy-critical?style=for-the-badge&logo=shield)](SECURITY.md)

<p align="center">
  <strong>AI-powered vulnerability scanner with ML-based CVSS scoring, authenticated scanning, CDN/WAF bypass detection, and comprehensive attack surface mapping.</strong>
</p>

---

**⚠️ Authorized Use Only** — Only scan targets you own or have explicit written permission to test.

</div>

---

## 🎯 Overview

AI Vulnerability Scanner V2 is a professional-grade, AI-powered web application security testing framework. It combines traditional vulnerability detection techniques with machine learning classification to provide accurate, actionable security assessments.

### What Sets This Apart

| Feature | Traditional Scanners | **AI Vuln Scanner V2** |
|---------|---------------------|----------------------|
| Vulnerability Classification | Rule-based severity | **ML-powered CVSS scoring** with NVD-trained model |
| CDN Detection | ❌ None | **Automatic CDN/WAF fingerprinting** with origin IP discovery |
| Stored XSS | Single-pass | **Two-pass inject → verify** detection |
| IDOR Testing | Basic param fuzzing | **Auth-context differential analysis** |
| IP Intelligence | ❌ None | **Full recon: ASN, PTR, CDN bypass, internal IP leakage** |
| Authentication | Cookie only | **Form login, cookie, bearer token** with session verification |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Streamlit Dashboard (app.py)                  │
│              Real-time progress · Vuln cards · Filters          │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                 Scanner Engine V2 (Orchestrator)                │
│                                                                 │
│  Phase 0 ─── IP Recon ──────── DNS · CDN · ASN · Origin IP    │
│  Phase 1 ─── Authentication ── Form · Cookie · Token           │
│  Phase 2 ─── Crawling ──────── BFS · Auth-aware · Depth 3     │
│  Phase 3 ─── Directories ───── 40+ sensitive paths             │
│  Phase 4 ─── Headers ───────── Security header audit           │
│  Phase 5 ─── Per-page ──────── XSS · SQLi · Open Redirect     │
│  Phase 6 ─── Stored XSS ────── Two-pass inject/verify         │
│  Phase 7 ─── IDOR ──────────── Auth differential fuzzing       │
│  Phase 7b ── IP Leakage ────── Headers · HTML · JS · JSON     │
│  Phase 8 ─── AI Classification  ML CVSS · CWE · Dedup         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔍 Modules

### 🔎 IP Intelligence (Phase 0)

Pre-scan reconnaissance that runs before any crawling begins.

| Component | Capability |
|-----------|-----------|
| **IP Resolver** | DNS A/AAAA resolution, reverse DNS (PTR), ASN/RDAP lookup (org, country) |
| **CDN Detector** | Fingerprints 8 CDN providers via response headers (Cloudflare, CloudFront, Akamai, Fastly, Azure, GCP, Sucuri, Imperva) |
| **CDN Bypass** | Origin IP discovery via crt.sh SSL certificate history, HackerTarget DNS history, MX/SPF/NS record analysis |
| **IP Leakage** | Detects private IPs (RFC1918, loopback, link-local) in headers, HTML, JS files, and JSON API responses |

### ⚡ Vulnerability Detectors (Phases 3-7)

| Detector | Technique | CWE |
|----------|-----------|-----|
| **Cross-Site Scripting** | 11 payloads, URL params + form fields, reflection detection | CWE-79 |
| **Stored XSS** | Two-pass: inject marker → verify on other pages | CWE-79 |
| **SQL Injection** | Error-based (28 DB error patterns) + boolean-based differential | CWE-89 |
| **Open Redirect** | 22 redirect params × 4 payloads, server + client-side checks | CWE-601 |
| **IDOR** | ID fuzzing (numeric ±1/±2/+100, UUID), auth vs unauth differential | CWE-639 |
| **Directory Enumeration** | 40+ sensitive paths (.env, .git, /admin, API endpoints) | CWE-548 |
| **Security Headers** | Missing + weak header audit (HSTS, CSP, X-Frame-Options, etc.) | CWE-693 |
| **Internal IP Leakage** | 4-source scan: HTTP headers, HTML/comments, JS bundles, JSON APIs | CWE-200 |

### 🤖 AI Classification (Phase 8)

- **GradientBoosting classifier** trained on NVD-derived reference data (22 vuln types × 45 samples)
- Outputs: CVSS 3.1 score, severity rating, CWE ID, confidence level
- Automatic deduplication on `(type, url, parameter)` tuples

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/Tktirth/AI-VULN.-SCANNER-V2.git
cd AI-VULN.-SCANNER-V2

# Install dependencies
pip install -r requirements.txt

# Launch the scanner
streamlit run app.py
```

### Docker Deployment (Recommended)

You can run the scanner in a containerized environment using Docker.

```bash
# Clone the repository
git clone https://github.com/Tktirth/AI-VULN.-SCANNER-V2.git
cd AI-VULN.-SCANNER-V2

# Build and start using Docker Compose
docker compose up -d

# Or build and run using raw Docker commands
docker build -t ai-vuln-scanner .
docker run -d -p 8501:8501 --name vuln-scanner ai-vuln-scanner
```

The application will be available at `http://localhost:8501`.

### Cloud Deployment via GitHub Actions (GCP Cloud Run)

This repository includes an automated CI/CD pipeline (`.github/workflows/cloud-run-deploy.yml`) that deploys the application to Google Cloud Run automatically whenever changes are pushed to the `main` branch.

**Setup Instructions:**
1. Create a Service Account in your Google Cloud project (`web-vulnarebility-scanner`).
2. Grant it the following roles:
   - Cloud Run Admin (`roles/run.admin`)
   - Cloud Build Service Account (`roles/cloudbuild.builds.builder`)
   - Artifact Registry Administrator (`roles/artifactregistry.admin`)
   - Service Account User (`roles/iam.serviceAccountUser`)
3. Generate a JSON key for this Service Account.
4. Go to your GitHub Repository -> **Settings** -> **Secrets and variables** -> **Actions** -> **New repository secret**.
5. Name the secret `GCP_CREDENTIALS` and paste the entire JSON key as the value.

Once configured, pushing code to `main` will automatically build and deploy the app to Cloud Run.

### Usage

1. **Enter target URL** in the main input field
2. **Configure modules** in the sidebar (all enabled by default)
3. **Set authentication** if the target requires login
4. **Click ▶ SCAN** and watch real-time progress
5. **Review findings** with severity filters, CVSS charts, and detailed remediation
6. **Export** the JSON report for offline analysis

---

## 🔐 Authentication Modes

| Mode | Use Case | Config |
|------|----------|--------|
| **None** | Public-facing scan | Default |
| **Form Login** | Login page with username/password | Login URL + credentials + optional logged-in indicator |
| **Cookie** | Pre-existing session cookies | Paste `name=value` pairs |
| **Bearer Token** | API tokens / JWT | Token value + scheme (Bearer, Token, Basic, ApiKey) |

---

## 📊 Output

### Live Dashboard

- **Real-time progress** with phase-by-phase terminal output
- **IP Intelligence panel** showing target IP, ASN, CDN status, and origin IP discovery
- **Vulnerability cards** with severity badges, CVSS bars, CWE tags, payloads, and remediation
- **Filters** by severity, vulnerability type, and CWE ID
- **CVSS distribution chart** for at-a-glance risk assessment

### JSON Report

Structured export containing:

```json
{
  "report_metadata": { "tool", "version", "target", "timestamp" },
  "executive_summary": { "risk_level", "severity_breakdown", "stats" },
  "reconnaissance": {
    "target_intelligence": { "ip", "asn", "ptr", "country" },
    "cdn_detection": { "provider", "bypass_possible", "origin_ip" },
    "ssl_cert_domains": ["subdomain1.example.com", "..."],
    "dns_records": { "mx", "ns", "spf" }
  },
  "vulnerabilities": [ { "type", "severity", "cvss", "cwe", "evidence", "remediation" } ],
  "remediation_priority": [ { "type", "count", "max_severity" } ],
  "cwe_summary": [ { "cwe_id", "count", "max_cvss" } ]
}
```

---

## 📁 Project Structure

```
AI-VULN.-SCANNER-V2/
├── app.py                          # Streamlit dashboard UI
├── scanner_engine.py               # Scan orchestrator (8 phases)
├── crawler.py                      # BFS web crawler with auth support
├── requirements.txt                # Python dependencies
│
├── recon/                          # Phase 0: IP Intelligence
│   ├── __init__.py
│   ├── ip_resolver.py              # DNS resolution + CDN detection + ASN
│   └── cdn_bypass.py               # Origin IP discovery (5 methods)
│
├── detectors/                      # Phases 3-7: Vulnerability Detectors
│   ├── __init__.py
│   ├── xss_detector.py             # Reflected + Stored XSS
│   ├── sql_detector.py             # Error-based + Boolean SQLi
│   ├── header_detector.py          # Security header audit
│   ├── redirect_detector.py        # Open redirect detection
│   ├── directory_detector.py       # Sensitive path enumeration
│   ├── idor_detector.py            # IDOR fuzzing
│   └── ip_leakage.py              # Internal IP exposure (CWE-200)
│
├── ai/                             # Phase 8: ML Classification
│   └── vulnerability_ai.py         # GradientBoosting CVSS classifier
│
├── auth/                           # Authentication engine
│   └── auth_manager.py             # Form/cookie/token auth
│
├── utils/                          # Shared utilities
│   ├── request_manager.py          # HTTP session management
│   └── payloads.py                 # Payloads, wordlists, signatures
│
├── reports/                        # Report generation
│   └── report_generator.py         # JSON report builder
│
├── SECURITY.md                     # Security policy
├── CONTRIBUTING.md                 # Contribution guidelines
└── LICENSE                         # MIT License
```

---

## 🛡️ Ethical Use & Legal Notice

This tool is intended for **authorized security testing and educational purposes only**.

- ✅ Scan your own applications
- ✅ Scan with explicit written authorization
- ✅ Use for security research and education
- ❌ **Never scan without permission**
- ❌ **Never use for unauthorized access**
- ❌ **Never use for malicious purposes**

Unauthorized computer access is illegal under the **Computer Fraud and Abuse Act (CFAA)**, **UK Computer Misuse Act**, and equivalent legislation worldwide. The authors assume **no liability** for misuse.

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Coding standards and detector module patterns
- Finding dict format specification
- Commit conventions
- Architecture overview

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <sub>Built for security professionals, by security enthusiasts.</sub>
</div>
