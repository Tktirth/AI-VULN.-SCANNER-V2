"""
IP resolver and CDN detection module.

Resolves domain → IP addresses, performs reverse DNS (PTR) lookups,
queries ASN/RDAP data via ipwhois, and detects CDN providers by
inspecting HTTP response headers.

All operations are synchronous.  Errors are caught internally —
the resolver always returns a partial-result dict, never raises.
"""

import logging
import socket
import time
from typing import Any, Dict, List, Optional

from ipwhois import IPWhois

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level ASN cache  {ip: {"data": {…}, "ts": float}}
# ---------------------------------------------------------------------------
_asn_cache: Dict[str, Dict[str, Any]] = {}
_ASN_CACHE_TTL = 86400  # 24 hours

# ---------------------------------------------------------------------------
# CDN header signatures
# Each entry: list of (header_name, value_contains_or_None)
# ---------------------------------------------------------------------------
CDN_HEADER_SIGNATURES: Dict[str, List[tuple]] = {
    "Cloudflare": [
        ("CF-RAY", None),
        ("CF-Cache-Status", None),
        ("Server", "cloudflare"),
    ],
    "AWS CloudFront": [
        ("X-Amz-Cf-Id", None),
        ("X-Cache", "cloudfront"),
        ("Via", "CloudFront"),
    ],
    "Akamai": [
        ("X-Check-Cacheable", None),
        ("X-Akamai-Request-ID", None),
        ("X-Serial", None),
        ("Server", "AkamaiGHost"),
    ],
    "Fastly": [
        ("X-Served-By", None),
        ("Fastly-Request-ID", None),
        ("X-Cache", "HIT"),
        ("Via", "varnish"),
    ],
    "Azure CDN": [
        ("X-Azure-Ref", None),
        ("X-FD-HealthProbe", None),
    ],
    "Google Cloud CDN": [
        ("Via", "google"),
        ("X-Google-Cache-Control", None),
    ],
    "Sucuri": [
        ("X-Sucuri-ID", None),
        ("X-Sucuri-Cache", None),
    ],
    "Imperva": [
        ("X-Iinfo", None),
        ("X-CDN", "Imperva"),
    ],
}


class SSRFGuardError(Exception):
    """Raised when target resolves to a private IP (SSRF prevention)."""
    pass


def resolve_target(domain_or_url: str, request_manager: Any) -> Dict[str, Any]:
    """
    Validates the target URL/domain to prevent SSRF before running lookup.
    Raises SSRFGuardError if the target resolves to a private/internal IP address.
    """
    from urllib.parse import urlparse
    import ipaddress

    if "://" in domain_or_url:
        parsed = urlparse(domain_or_url)
        domain = parsed.hostname or ""
    else:
        domain = domain_or_url

    # Resolve target DNS to check for private IPs
    try:
        addr_infos = socket.getaddrinfo(domain, None)
        seen = set()
        for family, _type, _proto, _canon, sockaddr in addr_infos:
            ip_str = sockaddr[0]
            if ip_str in seen:
                continue
            seen.add(ip_str)
            
            ip = ipaddress.ip_address(ip_str)
            if (
                ip.is_private or
                ip.is_loopback or
                ip.is_link_local or
                ip.is_multicast or
                ip.is_unspecified
            ):
                raise SSRFGuardError(f"SSRF Blocked: Target {domain_or_url} resolves to private/reserved IP {ip_str}")
    except socket.gaierror as exc:
        logger.debug("DNS resolution failed in SSRF check: %s", exc)

    resolver = IPResolver()
    return resolver.resolve(domain, request_manager)


class IPResolver:
    """Resolves a domain to IPs, performs ASN lookup, and detects CDN usage."""

    # ------------------------------------------------------------------ #
    #  Public API                                                         #
    # ------------------------------------------------------------------ #
    def resolve(self, domain: str, request_manager: Any) -> Dict[str, Any]:
        """Resolve *domain* and return a comprehensive recon dict.

        Parameters
        ----------
        domain:
            Bare domain name (e.g. ``example.com``).
        request_manager:
            A ``RequestManager`` instance whose ``.get(url)`` method returns
            an ``Optional[requests.Response]``.

        Returns
        -------
        dict
            Always contains every documented key; values may be ``None``
            or empty when individual steps fail.
        """
        result: Dict[str, Any] = {
            "target_domain": domain,
            "resolved_ips": [],
            "primary_ip": None,
            "is_behind_cdn": False,
            "cdn_provider": None,
            "cdn_evidence": None,
            "asn_number": None,
            "asn_org": None,
            "hosting_country": None,
            "ptr_record": None,
            "ipv6_addresses": [],
        }

        try:
            # Step 1 — DNS resolution
            resolved_ips, primary_ip, ipv6_addresses = self._resolve_dns(domain)
            result["resolved_ips"] = resolved_ips
            result["primary_ip"] = primary_ip
            result["ipv6_addresses"] = ipv6_addresses

            # Step 2 — Reverse DNS (PTR)
            if primary_ip:
                result["ptr_record"] = self._reverse_dns(primary_ip)

            # Step 3 — ASN / RDAP lookup
            if primary_ip:
                asn_info = self._lookup_asn(primary_ip)
                result["asn_number"] = asn_info.get("asn_number")
                result["asn_org"] = asn_info.get("asn_org")
                result["hosting_country"] = asn_info.get("hosting_country")

            # Step 4 — CDN detection via response headers
            cdn_info = self._detect_cdn(domain, request_manager)
            result["is_behind_cdn"] = cdn_info["is_behind_cdn"]
            result["cdn_provider"] = cdn_info["cdn_provider"]
            result["cdn_evidence"] = cdn_info["cdn_evidence"]

        except Exception as exc:
            logger.debug("IPResolver.resolve() top-level error for %s: %s", domain, exc)

        return result

    # ------------------------------------------------------------------ #
    #  Step 1 — DNS resolution                                            #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _resolve_dns(domain: str) -> tuple:
        """Return (resolved_ips, primary_ip, ipv6_addresses).

        Uses ``socket.getaddrinfo`` to collect both A and AAAA records.
        """
        resolved_ips: List[str] = []
        primary_ip: Optional[str] = None
        ipv6_addresses: List[str] = []

        try:
            addr_infos = socket.getaddrinfo(domain, None)
            seen: set = set()
            for family, _type, _proto, _canon, sockaddr in addr_infos:
                ip = sockaddr[0]
                if ip in seen:
                    continue
                seen.add(ip)
                resolved_ips.append(ip)
                if family == socket.AF_INET:
                    if primary_ip is None:
                        primary_ip = ip
                elif family == socket.AF_INET6:
                    ipv6_addresses.append(ip)
        except socket.gaierror as exc:
            logger.debug("DNS resolution failed for %s: %s", domain, exc)

        return resolved_ips, primary_ip, ipv6_addresses

    # ------------------------------------------------------------------ #
    #  Step 2 — Reverse DNS                                               #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _reverse_dns(ip: str) -> Optional[str]:
        """Return PTR record for *ip*, or ``None`` on failure."""
        try:
            hostname, _aliases, _addrs = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError) as exc:
            logger.debug("Reverse DNS failed for %s: %s", ip, exc)
            return None

    # ------------------------------------------------------------------ #
    #  Step 3 — ASN / RDAP lookup (cached)                                #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _lookup_asn(ip: str) -> Dict[str, Optional[str]]:
        """Query RDAP for ASN data, with a 24-hour in-memory cache."""
        global _asn_cache

        now = time.time()

        # Check cache
        cached = _asn_cache.get(ip)
        if cached and (now - cached["ts"]) < _ASN_CACHE_TTL:
            return cached["data"]

        asn_info: Dict[str, Optional[str]] = {
            "asn_number": None,
            "asn_org": None,
            "hosting_country": None,
        }

        try:
            obj = IPWhois(ip)
            rdap = obj.lookup_rdap(depth=1, asn_methods=["whois", "dns", "http"])
            asn_raw = rdap.get("asn")
            if asn_raw:
                asn_info["asn_number"] = f"AS{asn_raw}"
            asn_info["asn_org"] = rdap.get("asn_description")
            asn_info["hosting_country"] = rdap.get("asn_country_code")
        except Exception as exc:
            logger.debug("ASN lookup failed for %s: %s", ip, exc)

        _asn_cache[ip] = {"data": asn_info, "ts": now}
        return asn_info

    # ------------------------------------------------------------------ #
    #  Step 4 — CDN detection                                             #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _detect_cdn(domain: str, request_manager: Any) -> Dict[str, Any]:
        """Issue a GET to *domain* and match response headers to CDN signatures."""
        cdn_result: Dict[str, Any] = {
            "is_behind_cdn": False,
            "cdn_provider": None,
            "cdn_evidence": None,
        }

        try:
            resp = request_manager.get(f"https://{domain}/")
            if resp is None:
                return cdn_result

            headers = {k.lower(): v for k, v in resp.headers.items()}

            for cdn_name, checks in CDN_HEADER_SIGNATURES.items():
                for header, value_contains in checks:
                    header_lower = header.lower()
                    if header_lower not in headers:
                        continue

                    actual_value = headers[header_lower]

                    if value_contains is None:
                        # Header exists — match
                        cdn_result["is_behind_cdn"] = True
                        cdn_result["cdn_provider"] = cdn_name
                        cdn_result["cdn_evidence"] = (
                            f"Header: {header}: {actual_value}"
                        )
                        return cdn_result

                    if value_contains.lower() in actual_value.lower():
                        cdn_result["is_behind_cdn"] = True
                        cdn_result["cdn_provider"] = cdn_name
                        cdn_result["cdn_evidence"] = (
                            f"Header: {header}: {actual_value}"
                        )
                        return cdn_result

        except Exception as exc:
            logger.debug("CDN detection failed for %s: %s", domain, exc)

        return cdn_result
