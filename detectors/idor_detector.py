"""
IDOR (Insecure Direct Object Reference) detector — V2.

Detection strategy:
1. Find URL parameters and path segments that look like object IDs (numeric, UUID-like)
2. Request the resource with the authenticated session
3. Increment/decrement the ID to reference a different object
4. Compare the authenticated response against an unauthenticated response
5. Flag IDOR if:
   - The modified ID returns 200 with substantially different content (different object)
   - OR the unauthenticated session can access the same resource as the auth session

This is heuristic — it cannot know what data *should* be accessible.
The scanner flags cases where ID enumeration changes response content
meaningfully, which is a strong IDOR signal in most applications.
"""

import re
import logging
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
from typing import List, Dict, Any, Optional

from utils.payloads import IDOR_PARAMS

logger = logging.getLogger(__name__)

# Minimum response length difference to consider a meaningful content change
CONTENT_DIFF_THRESHOLD = 100

# Regex patterns for ID-like values in URLs and parameters
NUMERIC_ID_PATTERN = re.compile(r"^\d{1,10}$")
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
ALPHANUM_ID_PATTERN = re.compile(r"^[a-zA-Z0-9]{6,32}$")


def detect_idor(
    url: str,
    auth_request_manager,
    unauth_request_manager=None,
) -> List[Dict[str, Any]]:
    """
    Run IDOR detection on a URL using parameter enumeration and
    optional unauthenticated access comparison.

    Args:
        url: Target URL to test
        auth_request_manager: Authenticated HTTP session
        unauth_request_manager: Fresh unauthenticated session (optional but improves detection)

    Returns:
        List of IDOR vulnerability dicts
    """
    vulns = []

    # Test query string parameters
    param_vulns = _test_query_params(url, auth_request_manager, unauth_request_manager)
    vulns.extend(param_vulns)

    # Test path segments that look like IDs
    path_vulns = _test_path_segments(url, auth_request_manager, unauth_request_manager)
    vulns.extend(path_vulns)

    return vulns


from bs4 import BeautifulSoup

def _are_doms_different(html1: str, html2: str) -> bool:
    try:
        soup1 = BeautifulSoup(html1, "html.parser")
        soup2 = BeautifulSoup(html2, "html.parser")
        tags1 = [t.name for t in soup1.find_all() if t.name]
        tags2 = [t.name for t in soup2.find_all() if t.name]
        return tags1 != tags2
    except Exception:
        return html1 != html2

def _test_query_params(
    url: str,
    auth_rm,
    unauth_rm,
) -> List[Dict[str, Any]]:
    """Test query string parameters for IDOR."""
    vulns = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for param_name, param_values in params.items():
        original_value = param_values[0]

        # Only test parameters whose values look like IDs
        if not _looks_like_id(param_name, original_value):
            continue

        fuzzed_values = _generate_id_variants(original_value)

        # Get baseline authenticated response
        baseline = auth_rm.get(url)
        if not baseline or baseline.status_code not in (200, 201):
            continue

        for fuzzed_id in fuzzed_values:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = fuzzed_id
            test_url = (
                f"{parsed.scheme}://{parsed.netloc}"
                f"{parsed.path}?{urlencode(test_params)}"
            )

            try:
                auth_resp = auth_rm.get(test_url)
                if not auth_resp:
                    continue

                # 401/403 response on fuzzed ID does NOT produce a finding
                if auth_resp.status_code in (401, 403):
                    continue

                if auth_resp.status_code not in (200, 201):
                    continue

                # Replace content length comparison with structural DOM comparison
                if not _are_doms_different(auth_resp.text, baseline.text):
                    continue

                # If we have an unauth session, compare access
                if unauth_rm:
                    unauth_resp = unauth_rm.get(test_url)
                    if unauth_resp and unauth_resp.status_code == 200:
                        if not _are_doms_different(unauth_resp.text, auth_resp.text):
                            # Unauth can see the same content as auth — definite IDOR
                            vulns.append(_build_idor_vuln(
                                url=url,
                                test_url=test_url,
                                param=param_name,
                                original_id=original_value,
                                fuzzed_id=fuzzed_id,
                                evidence=(
                                    f"Unauthenticated session accessed resource "
                                    f"'{param_name}={fuzzed_id}' — same structural DOM content as authenticated session"
                                ),
                                confirmed=True,
                            ))
                            break

                # Content changed but we couldn't confirm with unauth — potential IDOR
                vulns.append(_build_idor_vuln(
                    url=url,
                    test_url=test_url,
                    param=param_name,
                    original_id=original_value,
                    fuzzed_id=fuzzed_id,
                    evidence=(
                        f"Changing '{param_name}' from '{original_value}' to '{fuzzed_id}' "
                        f"returned structurally different DOM response — "
                        f"possible unauthorized object access"
                    ),
                    confirmed=False,
                ))
                break

            except Exception as e:
                logger.debug(f"IDOR param test error [{url}]: {e}")

    return vulns


def _test_path_segments(
    url: str,
    auth_rm,
    unauth_rm,
) -> List[Dict[str, Any]]:
    """Test URL path segments that look like object IDs."""
    vulns = []
    parsed = urlparse(url)
    segments = [s for s in parsed.path.split("/") if s]

    for i, segment in enumerate(segments):
        if not NUMERIC_ID_PATTERN.match(segment):
            continue

        original_id = segment
        fuzzed_values = _generate_id_variants(original_id)

        baseline = auth_rm.get(url)
        if not baseline or baseline.status_code not in (200, 201):
            continue

        for fuzzed_id in fuzzed_values:
            new_segments = segments.copy()
            new_segments[i] = fuzzed_id
            new_path = "/" + "/".join(new_segments)
            test_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
            if parsed.query:
                test_url += f"?{parsed.query}"

            try:
                auth_resp = auth_rm.get(test_url)
                if not auth_resp:
                    continue

                # 401/403 response on fuzzed ID does NOT produce a finding
                if auth_resp.status_code in (401, 403):
                    continue

                if auth_resp.status_code not in (200, 201):
                    continue

                if not _are_doms_different(auth_resp.text, baseline.text):
                    continue

                if unauth_rm:
                    unauth_resp = unauth_rm.get(test_url)
                    if unauth_resp and unauth_resp.status_code == 200:
                        if not _are_doms_different(unauth_resp.text, auth_resp.text):
                            vulns.append(_build_idor_vuln(
                                url=url,
                                test_url=test_url,
                                param=f"path[{i}]",
                                original_id=original_id,
                                fuzzed_id=fuzzed_id,
                                evidence=(
                                    f"Unauthenticated access to path ID '{fuzzed_id}' "
                                    f"returned same structural DOM content as authenticated session"
                                ),
                                confirmed=True,
                            ))
                            break

                vulns.append(_build_idor_vuln(
                    url=url,
                    test_url=test_url,
                    param=f"path segment /{segment}/",
                    original_id=original_id,
                    fuzzed_id=fuzzed_id,
                    evidence=(
                        f"Path ID changed from '{original_id}' → '{fuzzed_id}', "
                        f"response returned structurally different DOM"
                    ),
                    confirmed=False,
                ))
                break

            except Exception as e:
                logger.debug(f"IDOR path test error [{test_url}]: {e}")

    return vulns



# ── Helpers ───────────────────────────────────────────────────────────────────

def _looks_like_id(param_name: str, value: str) -> bool:
    """Return True if this parameter name/value combination looks like an object ID."""
    name_lower = param_name.lower()
    is_id_name = any(id_param in name_lower for id_param in IDOR_PARAMS)
    is_id_value = (
        NUMERIC_ID_PATTERN.match(value) is not None
        or UUID_PATTERN.match(value) is not None
    )
    return is_id_name or is_id_value


def _generate_id_variants(original: str) -> List[str]:
    """Generate adjacent ID values to fuzz with."""
    variants = []
    if NUMERIC_ID_PATTERN.match(original):
        base = int(original)
        for delta in [1, -1, 2, -2, 3, 100]:
            candidate = base + delta
            if candidate > 0:
                variants.append(str(candidate))
    elif UUID_PATTERN.match(original):
        # For UUIDs, try a known test UUID
        variants = ["00000000-0000-0000-0000-000000000001"]
    else:
        variants = []
    return variants


def _build_idor_vuln(
    url: str,
    test_url: str,
    param: str,
    original_id: str,
    fuzzed_id: str,
    evidence: str,
    confirmed: bool,
) -> Dict[str, Any]:
    confidence = "Confirmed" if confirmed else "Potential"
    return {
        "type": "IDOR",
        "subtype": "IDOR — Unauthorized Access",
        "url": url,
        "test_url": test_url,
        "parameter": param,
        "payload": f"{original_id} → {fuzzed_id}",
        "method": "GET",
        "evidence": evidence,
        "confidence": confidence,
        "description": (
            f"{confidence} IDOR in parameter '{param}'. "
            f"Changing the ID from '{original_id}' to '{fuzzed_id}' "
            f"accessed a different object's data. "
            f"The application does not verify the requesting user "
            f"has authorization to access the referenced resource."
        ),
        "remediation": (
            "Implement server-side authorization checks on every object access. "
            "Never rely solely on the client-supplied ID. "
            "Use indirect references (hashed/opaque tokens) instead of sequential integers. "
            "Verify object ownership against the authenticated session on every request."
        ),
    }
