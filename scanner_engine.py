"""
V2 Scanner Engine.
Orchestrates: auth → crawl → detect (XSS, stored XSS, SQLi, IDOR, headers, redirect, dirs) → AI classify → report.
"""

import logging
import time
from typing import List, Dict, Any, Optional, Callable

from crawler import WebCrawler
from detectors.xss_detector import detect_xss, detect_stored_xss
from detectors.sql_detector import detect_sqli
from detectors.header_detector import detect_missing_headers
from detectors.redirect_detector import detect_open_redirect
from detectors.directory_detector import detect_directories
from detectors.idor_detector import detect_idor
from detectors.ip_leakage import detect_ip_leakage
from detectors.ssrf_detector import detect_ssrf
from detectors.csrf_detector import detect_csrf
from detectors.path_traversal_detector import detect_path_traversal
from ai.vulnerability_ai import VulnerabilityClassifierV2
from utils.request_manager import RequestManager
from recon.ip_resolver import IPResolver
from recon.cdn_bypass import CDNBypassFinder

logger = logging.getLogger(__name__)


class ScannerEngineV2:
    """
    Full V2 scanning pipeline with authentication support,
    stored XSS two-pass detection, IDOR fuzzing, and CVSS scoring.
    """

    def __init__(
        self,
        target_url: str,
        # Auth config
        auth_mode: str = "none",          # "none" | "form" | "cookie" | "token"
        login_url: str = "",
        username: str = "",
        password: str = "",
        cookies: Optional[Dict[str, str]] = None,
        token: str = "",
        token_scheme: str = "Bearer",
        logged_in_indicator: str = "",
        # Module toggles
        scan_xss: bool = True,
        scan_stored_xss: bool = True,
        scan_sqli: bool = True,
        scan_headers: bool = True,
        scan_redirect: bool = True,
        scan_directories: bool = True,
        scan_idor: bool = True,
        scan_recon: bool = True,
        scan_ip_leakage: bool = True,
        # Tuning
        max_pages: int = 20,
        request_timeout: int = 10,
        request_delay: float = 0.3,
    ):
        self.target_url = target_url.rstrip("/")
        self.auth_mode = auth_mode
        self.login_url = login_url
        self.username = username
        self.password = password
        self.cookies = cookies or {}
        self.token = token
        self.token_scheme = token_scheme
        self.logged_in_indicator = logged_in_indicator

        self.scan_xss = scan_xss
        self.scan_stored_xss = scan_stored_xss
        self.scan_sqli = scan_sqli
        self.scan_headers = scan_headers
        self.scan_redirect = scan_redirect
        self.scan_directories = scan_directories
        self.scan_idor = scan_idor
        self.scan_recon = scan_recon
        self.scan_ip_leakage = scan_ip_leakage
        self.max_pages = max_pages

        self.auth_rm = RequestManager(timeout=request_timeout, delay=request_delay)
        self.unauth_rm = RequestManager(timeout=request_timeout, delay=request_delay)
        self.classifier = VulnerabilityClassifierV2()

        self.vulnerabilities: List[Dict[str, Any]] = []
        self.scanned_urls: List[str] = []
        self.auth_status: Dict[str, Any] = {"authenticated": False, "message": "No auth configured"}
        self.recon_data: Dict[str, Any] = {}
        self.scan_start: Optional[float] = None
        self.scan_end: Optional[float] = None

    def run(self, progress_callback: Optional[Callable] = None) -> List[Dict[str, Any]]:
        self.scan_start = time.time()
        self.vulnerabilities = []

        def _p(phase, pct, msg):
            if progress_callback:
                progress_callback(phase, pct, msg)
            logger.info(f"[{phase}] {pct*100:.0f}% {msg}")

        # ── Phase 1: Authentication ─────────────────────────────────────────
        _p("auth", 0.0, "Setting up authentication...")
        self._setup_auth()
        auth_msg = self.auth_status["message"]
        _p("auth", 1.0, f"Auth: {auth_msg}")

        # ── Phase 0: IP Reconnaissance ──────────────────────────────────────
        if self.scan_recon:
            _p("recon", 0.0, "Starting IP intelligence gathering...")
            from urllib.parse import urlparse
            parsed_domain = urlparse(self.target_url).netloc
            # Strip port if present
            if ":" in parsed_domain:
                parsed_domain = parsed_domain.split(":")[0]

            self.recon_data = {
                "target_domain": parsed_domain,
            }

            # Component A — IP Resolution + CDN Detection + ASN
            resolver = IPResolver()
            ip_info = resolver.resolve(parsed_domain, self.auth_rm)
            self.recon_data.update(ip_info)
            _p("recon", 0.4, f"IP resolved: {ip_info.get('primary_ip', 'unknown')} "
                              f"| CDN: {ip_info.get('cdn_provider', 'None')}")

            # Component B — CDN Bypass (only if CDN detected)
            if ip_info.get("is_behind_cdn"):
                _p("recon", 0.5, f"CDN detected ({ip_info['cdn_provider']}). "
                                  "Attempting origin IP discovery...")
                bypass_finder = CDNBypassFinder()
                bypass_info = bypass_finder.find_origin(parsed_domain)
                self.recon_data.update(bypass_info)
                if bypass_info.get("cdn_bypass_possible"):
                    origin = bypass_info.get("most_likely_origin_ip", "unknown")
                    _p("recon", 0.9, f"Potential origin IP found: {origin}")
                else:
                    _p("recon", 0.9, "No origin IP discovered — CDN hygiene appears good.")
            else:
                self.recon_data.update({
                    "cdn_bypass_possible": False,
                    "origin_ip_candidates": [],
                    "cdn_bypass_note": "Target not behind CDN",
                    "ssl_cert_domains": [],
                    "mx_records": [],
                    "spf_ip_ranges": [],
                    "ns_records": [],
                    "most_likely_origin_ip": None,
                    "origin_discovery_method": None,
                })

            self.recon_data["internal_ips_found"] = 0
            self.recon_data["internal_ip_locations"] = []
            _p("recon", 1.0, "Recon complete.")

        # ── Phase 2: Crawl ──────────────────────────────────────────────────
        _p("crawl", 0.0, f"Crawling {self.target_url}")
        crawler = WebCrawler(
            base_url=self.target_url,
            request_manager=self.auth_rm,
            max_pages=self.max_pages,
        )
        discovered = crawler.crawl(
            progress_callback=lambda c, t, u: _p(
                "crawl", min(c / max(t, 1), 0.99), f"Crawled: {u[:55]}..."
            )
        )
        self.scanned_urls = discovered
        _p("crawl", 1.0, f"Found {len(discovered)} pages.")

        # ── Phase 3: Directory Discovery ────────────────────────────────────
        if self.scan_directories:
            _p("directories", 0.0, "Probing sensitive paths...")
            d = detect_directories(self.target_url, self.auth_rm)
            self.vulnerabilities.extend(d)
            _p("directories", 1.0, f"Found {len(d)} directory issues.")

        # ── Phase 4: Security Headers ───────────────────────────────────────
        if self.scan_headers:
            _p("headers", 0.0, "Auditing security headers...")
            h = detect_missing_headers(self.target_url, self.auth_rm)
            self.vulnerabilities.extend(h)
            _p("headers", 1.0, f"Found {len(h)} header issues.")

        # ── Phase 5: Per-page scanning ──────────────────────────────────────
        urls_to_scan = list({self.target_url} | set(crawler.get_urls_with_params()))
        urls_to_scan = urls_to_scan[:self.max_pages]

        from concurrent.futures import ThreadPoolExecutor

        # Define detectors to run on each page
        detectors = []
        if self.scan_xss:
            detectors.append(("XSS", detect_xss))
        if self.scan_sqli:
            detectors.append(("SQL Injection", detect_sqli))
        if self.scan_redirect:
            detectors.append(("Open Redirect", detect_open_redirect))
        
        # Add new detectors
        detectors.append(("SSRF", detect_ssrf))
        detectors.append(("CSRF", detect_csrf))
        detectors.append(("Path Traversal", detect_path_traversal))

        def scan_single_url(url: str) -> List[Dict[str, Any]]:
            logger.info(f"[CONCURRENCY_LOG] Started scanning {url} at {time.time()}")
            url_findings = []
            for det_name, det_fn in detectors:
                try:
                    url_findings.extend(det_fn(url, self.auth_rm))
                except Exception as e:
                    logger.error(f"Detector {det_name} error on {url}: {e}")
            logger.info(f"[CONCURRENCY_LOG] Finished scanning {url} at {time.time()}")
            return url_findings

        _p("scan", 0.0, f"Running concurrent vulnerability scans on {len(urls_to_scan)} pages...")
        
        all_url_findings = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(scan_single_url, url) for url in urls_to_scan]
            for i, fut in enumerate(futures):
                try:
                    all_url_findings.extend(fut.result())
                    _p("scan", (i + 1) / len(urls_to_scan), f"Completed scanning {i+1}/{len(urls_to_scan)} pages.")
                except Exception as e:
                    logger.error(f"Error in concurrent page scan: {e}")

        self.vulnerabilities.extend(all_url_findings)

        # ── Phase 6: Stored XSS (two-pass) ─────────────────────────────────
        if self.scan_stored_xss:
            _p("stored_xss", 0.0, "Running stored XSS two-pass detection...")
            stored_vulns = []
            for i, url in enumerate(urls_to_scan):
                _p("stored_xss", (i + 1) / max(len(urls_to_scan), 1),
                   f"Stored XSS inject: {url[:50]}...")
                try:
                    sv = detect_stored_xss(url, self.auth_rm, discovered)
                    stored_vulns.extend(sv)
                except Exception as e:
                    logger.error(f"Stored XSS error [{url}]: {e}")
            self.vulnerabilities.extend(stored_vulns)
            _p("stored_xss", 1.0, f"Stored XSS: {len(stored_vulns)} confirmed.")

        # ── Phase 7: IDOR ───────────────────────────────────────────────────
        if self.scan_idor:
            _p("idor", 0.0, "Running IDOR detection...")
            idor_vulns = []
            idor_urls = [u for u in discovered if "?" in u or self._has_id_segment(u)]
            for i, url in enumerate(idor_urls[:self.max_pages]):
                _p("idor", (i + 1) / max(len(idor_urls[:self.max_pages]), 1),
                   f"IDOR test: {url[:55]}...")
                try:
                    iv = detect_idor(
                        url,
                        auth_request_manager=self.auth_rm,
                        unauth_request_manager=self.unauth_rm if self.auth_status["authenticated"] else None,
                    )
                    idor_vulns.extend(iv)
                except Exception as e:
                    logger.error(f"IDOR error [{url}]: {e}")
            self.vulnerabilities.extend(idor_vulns)
            _p("idor", 1.0, f"IDOR: {len(idor_vulns)} findings.")

        # ── Phase 7b: Internal IP Leakage ───────────────────────────────────
        if self.scan_ip_leakage:
            _p("ip_leakage", 0.0, "Scanning for internal IP address leakage...")
            try:
                ip_leaks = detect_ip_leakage(
                    self.target_url, self.auth_rm, self.scanned_urls
                )
                self.vulnerabilities.extend(ip_leaks)
                # Update recon summary count if recon was run
                if self.recon_data:
                    self.recon_data["internal_ips_found"] = len(ip_leaks)
                    self.recon_data["internal_ip_locations"] = [
                        {"ip": v.get("evidence", ""), "url": v.get("url", ""),
                         "source": v.get("parameter", "")} for v in ip_leaks
                    ]
            except Exception as e:
                logger.error(f"IP leakage detection error: {e}")
                ip_leaks = []
            _p("ip_leakage", 1.0, f"IP leakage: {len(ip_leaks)} findings.")

        # ── Phase 8: AI Classification ──────────────────────────────────────
        _p("ai", 0.0, "Running AI CVSS classification...")
        self.vulnerabilities = self.classifier.classify_batch(self.vulnerabilities)
        self.vulnerabilities = self._deduplicate(self.vulnerabilities)
        self.vulnerabilities.sort(
            key=lambda v: v.get("severity_score", 0), reverse=True
        )
        _p("ai", 1.0, f"Done. {len(self.vulnerabilities)} unique findings.")

        self.scan_end = time.time()
        return self.vulnerabilities

    def _setup_auth(self):
        """Configure the authenticated session based on auth_mode."""
        from auth.auth_manager import AuthManager
        auth_mgr = AuthManager(self.auth_rm)

        if self.auth_mode == "none":
            self.auth_status = {"authenticated": False, "message": "Unauthenticated scan"}
            return

        if self.auth_mode == "form":
            if not self.login_url or not self.username or not self.password:
                self.auth_status = {"authenticated": False, "message": "Form auth: missing login_url, username, or password"}
                return
            success, msg = auth_mgr.form_login(
                self.login_url, self.username, self.password
            )
            if success and self.logged_in_indicator:
                verified = auth_mgr.verify_session(self.target_url, self.logged_in_indicator)
                if not verified:
                    msg = f"Login submitted but indicator '{self.logged_in_indicator}' not found — session may be invalid"
                    success = False
            self.auth_status = {"authenticated": success, "message": msg}
            return

        if self.auth_mode == "cookie":
            success, msg = auth_mgr.cookie_auth(self.cookies)
            self.auth_status = {"authenticated": success, "message": msg}
            return

        if self.auth_mode == "token":
            success, msg = auth_mgr.token_auth(self.token, self.token_scheme)
            self.auth_status = {"authenticated": success, "message": msg}
            return

        self.auth_status = {"authenticated": False, "message": f"Unknown auth mode: {self.auth_mode}"}

    def _has_id_segment(self, url: str) -> bool:
        """Check if URL path contains a numeric segment that looks like an ID."""
        import re
        from urllib.parse import urlparse
        path = urlparse(url).path
        return bool(re.search(r"/\d{1,10}(/|$)", path))

    def _deduplicate(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        unique = []
        for v in vulns:
            key = (v.get("type"), v.get("url"), v.get("parameter"))
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique

    def get_summary(self) -> Dict[str, Any]:
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        type_counts: Dict[str, int] = {}
        for v in self.vulnerabilities:
            s = v.get("severity", "Low")
            severity_counts[s] = severity_counts.get(s, 0) + 1
            t = v.get("type", "Unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        elapsed = (self.scan_end - self.scan_start) if self.scan_start and self.scan_end else 0
        return {
            "target_url": self.target_url,
            "total_vulnerabilities": len(self.vulnerabilities),
            "severity_breakdown": severity_counts,
            "type_breakdown": type_counts,
            "pages_scanned": len(self.scanned_urls),
            "requests_made": self.auth_rm.get_request_count(),
            "scan_duration_seconds": round(elapsed, 2),
            "authenticated": self.auth_status.get("authenticated", False),
            "auth_message": self.auth_status.get("message", ""),
            "recon_data": self.recon_data if self.recon_data else None,
        }

    def close(self):
        self.auth_rm.close()
        self.unauth_rm.close()
