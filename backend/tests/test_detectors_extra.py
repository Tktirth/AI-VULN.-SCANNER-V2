import pytest
import time
import socket
from unittest.mock import MagicMock, patch

from detectors.path_traversal_detector import detect_path_traversal
from detectors.xss_detector import detect_xss, detect_stored_xss
from detectors.sql_detector import detect_sqli
from detectors.idor_detector import detect_idor
from recon.ip_resolver import resolve_target, SSRFGuardError
from recon.cdn_bypass import CDNBypassFinder
from detectors.ip_leakage import detect_ip_leakage
from utils.nvd_client import NVDClient

# Mocks for RequestManager responses
class MockResponse:
    def __init__(self, text, status_code=200, headers=None, json_data=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self._json_data = json_data

    def json(self):
        if self._json_data is not None:
            return self._json_data
        import json
        return json.loads(self.text)

class MockRequestManager:
    def __init__(self, routes=None):
        self.routes = routes or {}
        self.request_count = 0

    def get(self, url, params=None, headers=None, allow_redirects=True):
        self.request_count += 1
        if params is None:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
        # Match URL
        for route_url, resp_fn in self.routes.items():
            if route_url in url:
                return resp_fn("GET", url, params)
        return MockResponse("Default baseline", 200)

    def post(self, url, data=None, headers=None, allow_redirects=True):
        self.request_count += 1
        for route_url, resp_fn in self.routes.items():
            if route_url in url:
                return resp_fn("POST", url, data)
        return MockResponse("Default post", 200)


# 1. Path Traversal Tests
def test_path_traversal_linux_success():
    def routes_fn(method, url, params):
        if "passwd" in url:
            return MockResponse("root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin", 200)
        return MockResponse("normal response", 200)

    rm = MockRequestManager({"/test": routes_fn})
    vulns = detect_path_traversal("http://example.com/test?file=normal.txt", rm)
    assert len(vulns) == 1
    assert vulns[0]["type"] == "Path Traversal"
    assert vulns[0]["subtype"] == "Local File Inclusion"
    assert "passwd" in vulns[0]["payload"]

def test_path_traversal_windows_success():
    def routes_fn(method, url, params):
        if "win.ini" in url:
            return MockResponse("[extensions]\n[fonts]\nsupport=1", 200)
        return MockResponse("normal response", 200)

    rm = MockRequestManager({"/test": routes_fn})
    vulns = detect_path_traversal("http://example.com/test?file=normal.txt", rm)
    assert len(vulns) == 1
    assert "win.ini" in vulns[0]["payload"]


# 2. XSS Tests (HTML-encoded reflection and stored XSS SVXSS_PROBE_7f3a9)
def test_xss_html_encoded_variant_reflection():
    # Literal HTML-encoded payload variant reflection
    def routes_fn(method, url, params):
        if params and any("&lt;script&gt;" in str(val) for val in params.values()):
            return MockResponse("&lt;script&gt;alert(1)&lt;/script&gt;", 200)
        return MockResponse("normal", 200)

    rm = MockRequestManager({"/test": routes_fn})
    vulns = detect_xss("http://example.com/test?param=test", rm)
    assert len(vulns) > 0

def test_stored_xss_marker_found():
    def routes_fn(method, url, data):
        if method == "POST":
            return MockResponse("Saved", 200)
        # Re-fetching returns the raw HTML body with the probe marker
        return MockResponse("<html><body>SVXSS_PROBE_7f3a9</body></html>", 200)

    rm = MockRequestManager({"/form": routes_fn})
    
    # We pass BeautifulSoup mock forms
    with patch("detectors.xss_detector.BeautifulSoup") as mock_bs:
        mock_form = MagicMock()
        mock_form.get.side_effect = lambda k, default=None: {"action": "/form", "method": "post"}.get(k, default)
        
        mock_input = MagicMock()
        mock_input.get.side_effect = lambda k, default=None: {"name": "comment", "type": "text"}.get(k, default)
        mock_form.find_all.return_value = [mock_input]
        
        mock_soup = MagicMock()
        mock_soup.find_all.return_value = [mock_form]
        mock_bs.return_value = mock_soup

        vulns = detect_stored_xss("http://example.com/form", rm, ["http://example.com/form"])
        assert len(vulns) == 1
        assert vulns[0]["type"] == "Stored XSS"
        assert "SVXSS_PROBE_7f3a9" in vulns[0]["evidence"]


# 3. SQLi Tests (Deduplication and Time-based SQLi)
def test_sqli_boolean_tested_only_once():
    boolean_tests = 0
    def routes_fn(method, url, params):
        nonlocal boolean_tests
        if params and ("1 AND 1=" in str(params.values()) or "1=1" in str(params.values())):
            boolean_tests += 1
            if "1=1" in str(params.values()):
                return MockResponse("Content length difference here between true and false matches - very long response content!", 200)
            else:
                return MockResponse("Short response", 200)
        return MockResponse("Content length difference here between true and false matches - very long response content!", 200)

    rm = MockRequestManager({"/test": routes_fn})
    # Run SQLi detection
    detect_sqli("http://example.com/test?id=5", rm)
    # The boolean injection should be evaluated exactly once (1 call to true and 1 to false, so 1 session pair test)
    assert boolean_tests <= 2

def test_sqli_time_based_threshold_exceeded():
    def routes_fn(method, url, params):
        if params and "SLEEP" in str(params.values()):
            time.sleep(0.5) # Simulate database delay
            return MockResponse("Delayed", 200)
        return MockResponse("Normal", 200)

    rm = MockRequestManager({"/test": routes_fn})
    
    # Let's patch time.time to simulate a 5.0 second elapsed duration
    with patch("time.time") as mock_time:
        mock_time.side_effect = [100.0, 105.0] # Duration of 5.0s
        vulns = detect_sqli("http://example.com/test?id=5", rm)
        time_vulns = [v for v in vulns if "Time-based" in v["subtype"] or "Time" in v["subtype"]]
        assert len(time_vulns) == 1
        assert "threshold 4.5s" in time_vulns[0]["evidence"]


# 4. IDOR Tests (401/403 skip, structural DOM comparison)
def test_idor_authz_controls_prevent_finding():
    def routes_fn(method, url, params):
        # Returns 403 Forbidden for fuzzed ID parameters
        return MockResponse("Forbidden", 403)

    rm = MockRequestManager({"/test": routes_fn})
    vulns = detect_idor("http://example.com/test?id=1", rm, rm)
    # Since it returned 403 on fuzzing, there should be zero findings
    assert len(vulns) == 0

def test_idor_structural_dom_comparison():
    # Returns 200 with different DOM structures (different tag lists)
    baseline_html = "<html><body><div>User Profile</div></body></html>"
    fuzzed_html = "<html><body><span>Different Page Structure</span><p>Details</p></body></html>"
    
    def routes_fn(method, url, params):
        if params and params.get("id") == ["2"]:
            return MockResponse(fuzzed_html, 200)
        return MockResponse(baseline_html, 200)

    rm = MockRequestManager({"/profile": routes_fn})
    vulns = detect_idor("http://example.com/profile?id=1", rm)
    assert len(vulns) == 1
    assert "structurally different DOM" in vulns[0]["evidence"]


# 5. SSRF Guard target resolution
def test_ssrf_resolver_raises_guard_error_on_private_ip():
    # Socket resolver mock returning private range IP
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0))]
        
        rm = MockRequestManager()
        with pytest.raises(SSRFGuardError):
            resolve_target("http://private-internal-domain.local", rm)


# 6. CDN Bypass Finder Tests
def test_cdn_bypass_skip_if_not_behind_cdn():
    finder = CDNBypassFinder()
    result = finder.find_origin("example.com", is_behind_cdn=False, cdn_detected=False)
    assert result["origin_ip_candidates"] == []
    assert "no bypass needed" in result["cdn_bypass_note"]


# 7. IP Leakage Tests (Headers, JSON Body, Global Deduplication, stream-read cap)
def test_ip_leakage_header_and_body_leaks_and_deduplication():
    def custom_routes(method, url, params):
        if "api" in url:
            return MockResponse("", 200, headers={"Content-Type": "application/json"}, json_data={"server": "10.0.0.5"})
        res = MockResponse("<html><body>Leaked IP: 10.0.0.5 in body comment <!-- 10.0.0.5 --></body></html>", 200, headers={"Content-Type": "text/html", "X-Backend-Server": "192.168.1.1"})
        return res

    rm = MockRequestManager({"/leak": custom_routes, "/api": custom_routes})
    findings = detect_ip_leakage("http://example.com/leak", rm, ["http://example.com/leak", "http://example.com/api"])
    
    # We leaked 10.0.0.5 (in body/json) and 192.168.1.1 (in header)
    # Global deduplication should ensure we only have 2 findings total, despite multiple occurrences
    ips = [f["evidence"] for f in findings]
    assert len(findings) == 2
    assert any("192.168.1.1" in str(ip) for ip in ips)
    assert any("10.0.0.5" in str(ip) for ip in ips)


# 8. NVD Client fallback
def test_nvd_client_fallback_on_503():
    # Querying a CVE when connection/server returns 503
    def routes_fn(method, url, params):
        return MockResponse("Service Unavailable", 503)

    rm = MockRequestManager({"services.nvd.nist.gov": routes_fn})
    client = NVDClient(request_manager=rm)
    
    # Query a known fallback CVE
    data = client.query_cve("CVE-2021-44228")
    assert data["title"] == "Log4Shell Apache Log4j RCE"
    assert data["cvss_score"] == 10.0
