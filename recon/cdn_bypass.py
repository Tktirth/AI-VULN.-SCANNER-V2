"""
CDN bypass / origin-IP discovery module.

When a target is behind a CDN (Cloudflare, CloudFront, etc.) this module
attempts to discover the **origin** server IP via five passive techniques:

1. SSL certificate history (crt.sh)
2. DNS history (HackerTarget)
3. MX record analysis
4. SPF record analysis
5. NS record analysis

All operations are synchronous.  Each technique is independently
wrapped in try/except so partial results are always returned.
"""

import ipaddress
import logging
import re
import socket
import time
from typing import Any, Dict, List, Optional, Set

import dns.resolver
import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known CDN edge-IP ranges (used to EXCLUDE false-positive candidates)
# ---------------------------------------------------------------------------
CLOUDFLARE_RANGES = [
    "104.16.0.0/12",
    "172.64.0.0/13",
    "131.0.72.0/22",
]
CLOUDFRONT_RANGES = [
    "13.32.0.0/15",
    "13.224.0.0/14",
    "54.230.0.0/15",
    "99.84.0.0/16",
]

_CDN_NETWORKS: List[ipaddress.IPv4Network] = [
    ipaddress.ip_network(cidr)
    for cidr in CLOUDFLARE_RANGES + CLOUDFRONT_RANGES
]

# ---------------------------------------------------------------------------
# Module-level caches  {key: {"data": …, "ts": float}}
# ---------------------------------------------------------------------------
_crtsh_cache: Dict[str, Dict[str, Any]] = {}
_hackertarget_cache: Dict[str, Dict[str, Any]] = {}
_CACHE_TTL = 86400  # 24 hours

# ---------------------------------------------------------------------------
# Source-confidence scoring
# ---------------------------------------------------------------------------
_SOURCE_SCORES: Dict[str, int] = {
    "ssl_san": 3,
    "dns_history": 2,
    "mx_record": 1,
    "spf_record": 1,
}


def _is_cdn_ip(ip_str: str) -> bool:
    """Return ``True`` if *ip_str* falls inside a known CDN edge range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        for net in _CDN_NETWORKS:
            if addr in net:
                return True
    except ValueError:
        pass
    return False


def _safe_resolve(hostname: str) -> Optional[str]:
    """Resolve *hostname* to a single IPv4 address, or ``None``."""
    try:
        infos = socket.getaddrinfo(hostname.rstrip("."), None, socket.AF_INET)
        if infos:
            return infos[0][4][0]
    except (socket.gaierror, OSError):
        pass
    return None


class CDNBypassFinder:
    """Attempts to locate origin-server IPs hidden behind a CDN."""

    def find_origin(self, domain: str, is_behind_cdn: bool = True, cdn_detected: bool = True) -> Dict[str, Any]:
        """Run all passive bypass techniques against *domain*.

        Parameters
        ----------
        domain:
            Bare domain (e.g. ``example.com``).
        is_behind_cdn:
            Set to ``False`` to short-circuit — the return dict will note
            that bypass is unnecessary.
        cdn_detected:
            Alternative name for is_behind_cdn to short-circuit.

        Returns
        -------
        dict
            Always contains every documented key; values may be empty
            when individual methods fail.
        """
        result: Dict[str, Any] = {
            "origin_ip_candidates": [],
            "most_likely_origin_ip": None,
            "origin_discovery_method": None,
            "ssl_cert_domains": [],
            "mx_records": [],
            "spf_ip_ranges": [],
            "ns_records": [],
            "cdn_bypass_possible": False,
            "cdn_bypass_note": None,
        }

        if not is_behind_cdn or not cdn_detected:
            result["cdn_bypass_note"] = (
                "Target not behind CDN — no bypass needed"
            )
            return result

        try:
            candidates: List[Dict[str, str]] = []

            # Method 1 — SSL certificate history
            ssl_domains = self._ssl_cert_history(domain)
            result["ssl_cert_domains"] = ssl_domains
            candidates.extend(
                self._candidates_from_ssl(domain, ssl_domains)
            )

            # Method 2 — DNS history (HackerTarget)
            candidates.extend(self._dns_history(domain))

            # Method 3 — MX records
            mx_records, mx_candidates = self._mx_records(domain)
            result["mx_records"] = mx_records
            candidates.extend(mx_candidates)

            # Method 4 — SPF records
            spf_ranges, spf_candidates = self._spf_records(domain)
            result["spf_ip_ranges"] = spf_ranges
            candidates.extend(spf_candidates)

            # Method 5 — NS records
            ns_records = self._ns_records(domain)
            result["ns_records"] = ns_records
            # NS IPs rarely reveal origin — tracked but not scored

            # Deduplicate & score
            result["origin_ip_candidates"] = candidates
            scored = self._score_candidates(candidates)
            if scored:
                winner_ip, winner_source = scored[0]
                result["most_likely_origin_ip"] = winner_ip
                result["origin_discovery_method"] = winner_source

            has_meaningful = any(
                c["confidence"] != "very_low" for c in candidates
            )
            result["cdn_bypass_possible"] = has_meaningful
            if has_meaningful:
                result["cdn_bypass_note"] = (
                    f"Potential origin IP found via {result['origin_discovery_method']}"
                )
            else:
                result["cdn_bypass_note"] = (
                    "No confident origin IP candidate discovered"
                )

        except Exception as exc:
            logger.debug(
                "CDNBypassFinder.find_origin() top-level error for %s: %s",
                domain, exc,
            )

        return result

    # ------------------------------------------------------------------ #
    #  Method 1 — SSL certificate history (crt.sh)                        #
    # ------------------------------------------------------------------ #
    def _ssl_cert_history(self, domain: str) -> List[str]:
        """Query crt.sh for certificate transparency logs."""
        global _crtsh_cache

        now = time.time()
        cached = _crtsh_cache.get(domain)
        if cached and (now - cached["ts"]) < _CACHE_TTL:
            return cached["data"]

        ssl_domains: List[str] = []
        try:
            time.sleep(0.5)  # polite pre-delay
            resp = requests.get(
                f"https://crt.sh/?q={domain}&output=json",
                timeout=8,
            )
            if resp.status_code == 200:
                entries = resp.json()
                seen: Set[str] = set()
                for entry in entries:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name and name not in seen:
                            seen.add(name)
                            ssl_domains.append(name)
        except Exception as exc:
            logger.debug("crt.sh query failed for %s: %s", domain, exc)

        _crtsh_cache[domain] = {"data": ssl_domains, "ts": now}
        return ssl_domains

    def _candidates_from_ssl(
        self, domain: str, ssl_domains: List[str]
    ) -> List[Dict[str, str]]:
        """Resolve SSL SANs that are subdomains of *domain* and filter CDN IPs."""
        candidates: List[Dict[str, str]] = []
        seen_ips: Set[str] = set()
        try:
            for san in ssl_domains:
                if san.endswith(f".{domain}") or san == domain:
                    ip = _safe_resolve(san)
                    if ip and ip not in seen_ips and not _is_cdn_ip(ip):
                        seen_ips.add(ip)
                        candidates.append({
                            "ip": ip,
                            "source": "ssl_san",
                            "confidence": "medium",
                        })
        except Exception as exc:
            logger.debug("SSL candidate extraction error: %s", exc)
        return candidates

    # ------------------------------------------------------------------ #
    #  Method 2 — DNS history (HackerTarget)                              #
    # ------------------------------------------------------------------ #
    def _dns_history(self, domain: str) -> List[Dict[str, str]]:
        """Query HackerTarget host-search for historical DNS records."""
        global _hackertarget_cache

        now = time.time()
        cached = _hackertarget_cache.get(domain)
        if cached and (now - cached["ts"]) < _CACHE_TTL:
            return cached["data"]

        candidates: List[Dict[str, str]] = []
        try:
            time.sleep(1.0)  # polite pre-delay
            resp = requests.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}",
                timeout=8,
            )
            if resp.status_code != 200:
                return candidates

            text = resp.text
            if "API count exceeded" in text:
                logger.warning(
                    "HackerTarget API rate-limit reached for %s", domain
                )
                return candidates

            seen_ips: Set[str] = set()
            for line in text.strip().splitlines():
                parts = line.split(",")
                if len(parts) >= 2:
                    ip = parts[1].strip()
                    if ip and ip not in seen_ips and not _is_cdn_ip(ip):
                        seen_ips.add(ip)
                        candidates.append({
                            "ip": ip,
                            "source": "dns_history",
                            "confidence": "medium",
                        })
        except Exception as exc:
            logger.debug("HackerTarget query failed for %s: %s", domain, exc)

        _hackertarget_cache[domain] = {"data": candidates, "ts": now}
        return candidates

    # ------------------------------------------------------------------ #
    #  Method 3 — MX records                                              #
    # ------------------------------------------------------------------ #
    def _mx_records(
        self, domain: str
    ) -> tuple:
        """Return (mx_records_list, candidates_list) from MX lookups."""
        mx_records: List[Dict[str, Optional[str]]] = []
        candidates: List[Dict[str, str]] = []
        try:
            answers = dns.resolver.resolve(domain, "MX")
            for rdata in answers:
                hostname = str(rdata.exchange).rstrip(".")
                ip = _safe_resolve(hostname)
                mx_records.append({"hostname": hostname, "ip": ip})
                if ip and not _is_cdn_ip(ip):
                    candidates.append({
                        "ip": ip,
                        "source": "mx_record",
                        "confidence": "low",
                    })
        except Exception as exc:
            logger.debug("MX lookup failed for %s: %s", domain, exc)
        return mx_records, candidates

    # ------------------------------------------------------------------ #
    #  Method 4 — SPF record analysis                                     #
    # ------------------------------------------------------------------ #
    def _spf_records(
        self, domain: str
    ) -> tuple:
        """Parse SPF TXT record for ip4:/ip6: directives."""
        spf_ranges: List[str] = []
        candidates: List[Dict[str, str]] = []
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if not txt.lower().startswith("v=spf1"):
                    continue
                # Extract ip4: and ip6: tokens
                for token in txt.split():
                    token_lower = token.lower()
                    if token_lower.startswith("ip4:") or token_lower.startswith("ip6:"):
                        ip_or_cidr = token.split(":", 1)[1]
                        spf_ranges.append(ip_or_cidr)
                        # Normalise to a single IP if it's a host address
                        ip_str = ip_or_cidr.split("/")[0]
                        if ip_str and not _is_cdn_ip(ip_str):
                            candidates.append({
                                "ip": ip_str,
                                "source": "spf_record",
                                "confidence": "low",
                            })
        except Exception as exc:
            logger.debug("SPF lookup failed for %s: %s", domain, exc)
        return spf_ranges, candidates

    # ------------------------------------------------------------------ #
    #  Method 5 — NS records                                              #
    # ------------------------------------------------------------------ #
    def _ns_records(self, domain: str) -> List[Dict[str, Optional[str]]]:
        """Resolve NS hostnames.  NS IPs rarely reveal the origin."""
        ns_records: List[Dict[str, Optional[str]]] = []
        try:
            answers = dns.resolver.resolve(domain, "NS")
            for rdata in answers:
                hostname = str(rdata.target).rstrip(".")
                ip = _safe_resolve(hostname)
                ns_records.append({"hostname": hostname, "ip": ip})
        except Exception as exc:
            logger.debug("NS lookup failed for %s: %s", domain, exc)
        return ns_records

    # ------------------------------------------------------------------ #
    #  Scoring & deduplication                                            #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _score_candidates(
        candidates: List[Dict[str, str]],
    ) -> List[tuple]:
        """Deduplicate by IP, sum source scores, return sorted list.

        Returns
        -------
        list[tuple[str, str]]
            ``[(ip, winning_source), …]`` sorted by descending score.
        """
        scores: Dict[str, int] = {}
        sources: Dict[str, str] = {}
        for c in candidates:
            ip = c["ip"]
            source = c["source"]
            pts = _SOURCE_SCORES.get(source, 0)
            scores[ip] = scores.get(ip, 0) + pts
            # Keep the highest-scoring source name for this IP
            if ip not in sources or pts > _SOURCE_SCORES.get(sources[ip], 0):
                sources[ip] = source

        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        return [(ip, sources[ip]) for ip, _score in ranked]
