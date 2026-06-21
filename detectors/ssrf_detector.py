"""
SSRF detector — V2.
"""
import logging
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

def detect_ssrf(url: str, request_manager) -> List[Dict[str, Any]]:
    """
    Detect potential SSRF vulnerabilities by finding candidate parameters
    named 'url' or 'redirect'.
    """
    vulns = []
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return vulns

        candidate_params = ["url", "redirect"]

        for param_name in params:
            if param_name.lower() in candidate_params:
                vulns.append({
                    "type": "SSRF",
                    "subtype": "SSRF Candidate Parameter",
                    "url": url,
                    "parameter": param_name,
                    "payload": "http://169.254.169.254/latest/meta-data/",
                    "method": "GET",
                    "evidence": f"Candidate parameter '{param_name}' found in URL",
                    "description": (
                        f"Potential Server-Side Request Forgery (SSRF) candidate parameter "
                        f"'{param_name}' was found in the URL. If the server fetches this "
                        f"URL internally without strict validation, it could allow attackers "
                        f"to access internal services or GCP/AWS metadata endpoints."
                    ),
                    "remediation": (
                        "Implement a strict whitelist of allowed domains/IPs. "
                        "Use URL parsing to validate targets before requesting. "
                        "Disable fetching internal/private IP ranges (RFC 1918)."
                    )
                })
    except Exception as e:
        logger.debug(f"SSRF detector error: {e}")
        
    return vulns
