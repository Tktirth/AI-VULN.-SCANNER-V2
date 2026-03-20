# AI Web Vulnerability Scanner — V2

V2 fixes every honest limitation listed in V1. It adds authenticated scanning, stored XSS two-pass detection, IDOR fuzzing, and a CVSS-scored AI classifier trained on NVD-derived data instead of fully synthetic labels.

---

## What's new in V2

**Authenticated scanning**  
Three auth modes: form-based login (auto-detects the form, handles CSRF tokens), cookie injection, and Bearer/API token injection. The crawler and all detectors run with the authenticated session, so pages behind login walls actually get tested.

**Stored XSS — two-pass detection**  
Pass 1 injects a uniquely marked payload into every form field. Pass 2 revisits the full crawled page list and checks if that marker was persisted and rendered back in any HTML response. That's how you catch stored XSS — you can't do it in one pass.

**IDOR fuzzing**  
Detects insecure direct object references by finding numeric and UUID-style IDs in URL parameters and path segments, generating adjacent values, and comparing responses. If an unauthenticated session is available alongside the authenticated one, it compares what both can access and flags confirmed IDOR when they see the same data.

**NVD-derived CVSS scoring**  
The classifier is now trained on a CVSS reference table built from NVD published base scores — SQLi at 9.8, stored XSS at 8.8, IDOR at 8.1, reflected XSS at 6.1, and so on. Every finding gets a CVSS score and a CWE ID.

---

## Getting started

```bash
cd ai-vuln-scanner-v2
pip install -r requirements.txt
streamlit run app.py
```

Opens at `http://localhost:8501`.

---

## Scan modes

**Public scan (no auth)**  
Just paste a URL and hit scan. Works exactly like V1 but with IDOR and stored XSS added.

**Form login**  
Enter the login page URL, username, and password in the sidebar. The scanner fetches the login form, extracts fields (including hidden CSRF tokens), submits credentials, and verifies the session before starting the crawl. Optionally provide a string that only appears when logged in — e.g., "Dashboard" or "Welcome back" — to confirm the session.

**Cookie injection**  
Paste your session cookies in `name=value` format, one per line. The scanner injects them into every request.

**Token auth**  
Paste your Bearer or API token. It gets injected as an `Authorization` header on every request.

---

## Project structure

```
ai-vuln-scanner-v2/
│
├── app.py                       ← Streamlit dashboard
├── scanner_engine.py            ← Orchestration — auth → crawl → detect → classify
├── crawler.py                   ← BFS crawler (works with auth sessions)
├── requirements.txt
│
├── auth/
│   └── auth_manager.py          ← Form login, cookie injection, token auth, session verify
│
├── ai/
│   └── vulnerability_ai.py      ← GradientBoosting classifier, NVD CVSS reference table, CWE mapping
│
├── detectors/
│   ├── xss_detector.py          ← Reflected XSS + stored XSS two-pass
│   ├── sql_detector.py          ← Error-based + boolean-based SQLi
│   ├── idor_detector.py         ← Numeric/UUID ID enumeration, auth vs unauth comparison
│   ├── header_detector.py       ← Missing headers, weak values, info leakage
│   ├── redirect_detector.py     ← Open redirect via parameter injection
│   └── directory_detector.py   ← 40+ sensitive path probes
│
├── utils/
│   ├── request_manager.py       ← Shared session, retry, SSL fallback, cookie/token injection
│   └── payloads.py              ← All payloads, IDOR params, stored XSS marker
│
└── reports/
    └── report_generator.py      ← JSON report with CVSS, CWE, remediation priority, CWE summary
```

---

## AI classifier — V2 changes

V1 used a RandomForest trained on synthetic labels. V2 uses a GradientBoosting classifier trained on a reference table derived from NVD published CVSS v3 base scores. The training features are the same but the labels are now anchored to real NVD data:

| Vulnerability | NVD CVSS | CWE |
|---|---|---|
| SQL Injection (error-based) | 9.8 | CWE-89 |
| Stored XSS | 8.8 | CWE-79 |
| IDOR | 8.1 | CWE-639 |
| Open Redirect | 6.1 | CWE-601 |
| Reflected XSS | 6.1 | CWE-79 |
| Missing HSTS | 5.9 | CWE-319 |
| Missing CSP | 6.1 | CWE-693 |
| Missing X-Frame-Options | 4.3 | CWE-1021 |
| Sensitive file exposed | 9.1 | CWE-200 |

The classifier outputs: `severity`, `cvss_score`, `cwe_id`, `cwe_description`.

---

## Honest limitations (what V2 still can't do)

**Broken access control beyond IDOR.** The IDOR detector catches object-level reference issues but won't find function-level access control failures — e.g., a regular user accessing an admin API endpoint. That requires knowing the application's intended authorization model.

**DOM-based XSS.** Reflected and stored XSS via server responses are covered. JavaScript-only DOM manipulation that never touches the server response isn't detectable without a headless browser.

**Business logic.** No automated scanner can understand your application's intent. Race conditions, improper workflow sequences, and logic-layer flaws require manual testing.

**Authenticated IDOR confidence.** Without two distinct user accounts to compare, the IDOR detector can only report "Potential" rather than "Confirmed". For confirmed IDOR, run the scan with one account's session and separately verify with a second account's cookies.

---

## Legal practice targets

| Target | Notes |
|---|---|
| `http://testphp.vulnweb.com` | Acunetix's intentionally vulnerable PHP app. Has SQLi, XSS, missing headers. Best starting point. |
| `https://ginandjuice.shop` | PortSwigger's vulnerable shop. Good for auth + redirect testing. |
| `http://zero.webappsecurity.com` | Demo banking app with a login form — good for testing form auth. |
| DVWA (local) | Run it locally with Docker. Full auth testing, stored XSS, IDOR all work. |

Only scan targets you own or have written permission to test.

---

## Author

**Tirth** — IT undergrad at GTU, IIT Delhi ethical hacking certified, IIT Guwahati AI/ML track.  
GitHub: [@Tktirth](https://github.com/Tktirth)

## 📜 License
This project is licensed under the MIT License.
