import logging
import json
from typing import Dict, Any, Optional
from backend import database

logger = logging.getLogger(__name__)

# Hardcoded reference dictionary of common CVEs to fallback to on error or 503
HARDCODED_NVD_FALLBACK: Dict[str, Dict[str, Any]] = {
    "CVE-2021-44228": {
        "title": "Log4Shell Apache Log4j RCE",
        "description": "Apache Log4j2 thread context lookup pattern vulnerable to remote code execution.",
        "severity": "Critical",
        "cvss_score": 10.0
    },
    "CVE-2017-5638": {
        "title": "Apache Struts RCE",
        "description": "Remote code execution vulnerability in Apache Struts Jakarta Multipart parser.",
        "severity": "Critical",
        "cvss_score": 9.8
    },
    "CVE-2020-0601": {
        "title": "Windows CryptoAPI Spoofing Vulnerability",
        "description": "A spoofing vulnerability exists in the way Windows CryptoAPI (Crypt32.dll) validates Elliptic Curve Cryptography (ECC) certificates.",
        "severity": "High",
        "cvss_score": 8.1
    }
}

class NVDClient:
    """
    Client for querying the NVD database.
    Caches responses in Redis for 24 hours.
    Falls back to a hardcoded reference dictionary if NVD returns 503 or errors.
    """

    def __init__(self, request_manager=None):
        self.request_manager = request_manager
        # Use database's redis client dynamically to allow test mocking
        self.redis_client = getattr(database, "redis_client", None)

    def query_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Query NVD for information on a specific CVE ID.
        Checks Redis cache first.
        """
        cache_key = f"nvd_cve_cache:{cve_id}"
        
        # Try checking Redis cache
        if self.redis_client:
            try:
                cached_val = self.redis_client.get(cache_key)
                if cached_val:
                    logger.info(f"NVD Cache HIT for {cve_id}")
                    return json.loads(cached_val)
            except Exception as e:
                logger.debug(f"Redis cache query error: {e}")

        # Cache miss or Redis unavailable, query NVD
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        try:
            # If no request_manager is supplied, import requests directly
            if self.request_manager:
                resp = self.request_manager.get(url)
            else:
                import requests
                resp = requests.get(url, timeout=10)

            if resp and resp.status_code == 200:
                data = resp.json()
                # Parse NVD json structure
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve_item = vulns[0].get("cve", {})
                    descriptions = cve_item.get("descriptions", [])
                    desc_text = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
                    metrics = cve_item.get("metrics", {})
                    
                    # Extract CVSS v3/v2 details
                    cvss_score = 0.0
                    severity = "Medium"
                    if "cvssMetricV31" in metrics:
                        metric = metrics["cvssMetricV31"][0].get("cvssData", {})
                        cvss_score = metric.get("baseScore", 0.0)
                        severity = metric.get("baseSeverity", "Medium")
                    elif "cvssMetricV30" in metrics:
                        metric = metrics["cvssMetricV30"][0].get("cvssData", {})
                        cvss_score = metric.get("baseScore", 0.0)
                        severity = metric.get("baseSeverity", "Medium")

                    result = {
                        "cve_id": cve_id,
                        "title": f"Vulnerability {cve_id}",
                        "description": desc_text or "No English description available in NVD.",
                        "severity": severity,
                        "cvss_score": cvss_score
                    }
                    
                    # Cache in Redis for 24 hours (86400 seconds)
                    if self.redis_client:
                        try:
                            self.redis_client.setex(cache_key, 86400, json.dumps(result))
                        except Exception as e:
                            logger.debug(f"Failed to cache NVD result in Redis: {e}")
                    return result
            else:
                status_val = resp.status_code if resp else 'None'
                logger.warning(f"NVD query returned non-200 status: {status_val}")
        except Exception as e:
            logger.error(f"NVD query error for {cve_id}: {e}")

        # Fallback to hardcoded reference dictionary
        logger.info(f"Using hardcoded NVD fallback reference for {cve_id}")
        fallback_data = HARDCODED_NVD_FALLBACK.get(
            cve_id,
            {
                "title": f"Vulnerability Reference {cve_id}",
                "description": f"Vulnerability details lookup for {cve_id} failed. Database query returned 503 or error.",
                "severity": "High",
                "cvss_score": 7.5
            }
        )
        return fallback_data
