"""
SARIF 2.1.0 exporter for AI Vulnerability Scanner V2.

Generates Static Analysis Results Interchange Format (SARIF) output
compliant with the OASIS SARIF v2.1.0 specification.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
TOOL_NAME = "AI Vulnerability Scanner V2"
TOOL_VERSION = "2.0.0"

# CWE taxonomy reference used by the tool component
_CWE_TAXONOMY = {
    "name": "CWE",
    "index": 0,
    "guid": "25F72D7E-8A92-459D-AD67-64853F788765",
}


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEVERITY_TO_LEVEL: Dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "informational": "note",
}


def _map_level(severity: str) -> str:
    """Map a vulnerability severity string to a SARIF result level."""
    return _SEVERITY_TO_LEVEL.get(severity.strip().lower(), "warning")


# ---------------------------------------------------------------------------
# Internal builders
# ---------------------------------------------------------------------------

def _build_rule(vuln: Dict[str, Any], rule_index: int) -> Dict[str, Any]:
    """Build a SARIF reportingDescriptor (rule) from a vulnerability dict."""
    vuln_type = vuln.get("type", "Unknown")
    subtype = vuln.get("subtype", "")
    rule_id = f"VS{rule_index:04d}-{vuln_type.replace(' ', '-').upper()}"

    rule: Dict[str, Any] = {
        "id": rule_id,
        "name": vuln_type,
        "shortDescription": {
            "text": f"{vuln_type}" + (f" ({subtype})" if subtype else ""),
        },
        "fullDescription": {
            "text": vuln.get("description", f"Detected {vuln_type} vulnerability."),
        },
        "defaultConfiguration": {
            "level": _map_level(vuln.get("severity", "medium")),
        },
    }

    # Attach help / remediation text
    remediation = vuln.get("remediation", "")
    if remediation:
        rule["help"] = {
            "text": remediation,
            "markdown": f"**Remediation:** {remediation}",
        }

    # CVSS properties
    cvss = vuln.get("cvss_score")
    if cvss:
        rule.setdefault("properties", {})["cvss_score"] = cvss

    # CWE taxa reference
    cwe_id = vuln.get("cwe_id", "")
    if cwe_id:
        numeric = cwe_id.replace("CWE-", "").strip()
        rule["relationships"] = [
            {
                "target": {
                    "id": cwe_id,
                    "index": int(numeric) if numeric.isdigit() else 0,
                    "toolComponent": _CWE_TAXONOMY,
                },
                "kinds": ["superset"],
            }
        ]

    return rule


def _build_result(
    vuln: Dict[str, Any],
    rule_id: str,
    rule_index: int,
    result_index: int,
    target_url: str,
) -> Dict[str, Any]:
    """Build a SARIF result object from a vulnerability dict."""
    # Primary message
    payload = vuln.get("payload", "")
    evidence = vuln.get("evidence", "")
    description = vuln.get("description", "")
    message_parts = [p for p in (description, evidence) if p]
    message_text = " | ".join(message_parts) or f"Vulnerability detected: {vuln.get('type', 'Unknown')}"

    result: Dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": _map_level(vuln.get("severity", "medium")),
        "message": {"text": message_text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": vuln.get("url", target_url),
                    },
                },
                "logicalLocations": [
                    {
                        "fullyQualifiedName": vuln.get("parameter", ""),
                        "kind": "parameter",
                    }
                ]
                if vuln.get("parameter")
                else [],
            }
        ],
    }

    # Fingerprint for deduplication
    vuln_id = f"VULN-{result_index + 1:04d}"
    result["fingerprints"] = {"primaryLocationLineHash": vuln_id}

    # Attach payload as a code flow snippet when present
    if payload:
        result["codeFlows"] = [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    "message": {"text": f"Payload: {payload}"},
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": vuln.get("test_url", vuln.get("url", target_url)),
                                        },
                                    },
                                },
                            }
                        ]
                    }
                ]
            }
        ]

    # Properties bag for extra metadata
    props: Dict[str, Any] = {}
    for key in ("confidence", "http_method", "method", "subtype", "injected_at"):
        val = vuln.get(key, "")
        if val:
            props[key] = val
    if props:
        result["properties"] = props

    return result


def _build_taxonomy() -> Dict[str, Any]:
    """Build a CWE taxonomy reference descriptor."""
    return {
        "name": "CWE",
        "version": "4.14",
        "informationUri": "https://cwe.mitre.org/",
        "organization": "MITRE",
        "shortDescription": {"text": "The MITRE Common Weakness Enumeration"},
        "isComprehensive": False,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_sarif(vulnerabilities: list, target_url: str) -> dict:
    """
    Generate a SARIF 2.1.0 compliant dict from a list of vulnerability dicts.

    Args:
        vulnerabilities: List of vulnerability dicts as produced by the
            scanner modules (keys: type, subtype, severity, cvss_score,
            cwe_id, url, parameter, method, payload, evidence, confidence,
            description, remediation, …).
        target_url: The base URL that was scanned.

    Returns:
        A Python dict representing a valid SARIF 2.1.0 log.
    """
    rules: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []
    rule_id_map: Dict[str, int] = {}  # vuln_type -> rule index

    for idx, vuln in enumerate(vulnerabilities):
        vuln_type = vuln.get("type", "Unknown")

        # De-duplicate rules by vulnerability type
        if vuln_type not in rule_id_map:
            rule_index = len(rules)
            rule = _build_rule(vuln, rule_index)
            rules.append(rule)
            rule_id_map[vuln_type] = rule_index
        else:
            rule_index = rule_id_map[vuln_type]

        rule_id = rules[rule_index]["id"]
        result = _build_result(vuln, rule_id, rule_index, idx, target_url)
        results.append(result)

    sarif: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "semanticVersion": TOOL_VERSION,
                        "informationUri": "https://github.com/AI-Vulnerability-Scanner/v2",
                        "rules": rules,
                        "supportedTaxonomies": [_CWE_TAXONOMY] if rules else [],
                    },
                },
                "taxonomies": [_build_taxonomy()] if rules else [],
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%SZ"
                        ),
                        "toolExecutionNotifications": [],
                    }
                ],
                "artifacts": [
                    {
                        "location": {"uri": target_url},
                        "sourceLanguage": "html",
                    }
                ],
            }
        ],
    }

    logger.info(
        "Generated SARIF report with %d results and %d rules",
        len(results),
        len(rules),
    )
    return sarif


def generate_sarif_string(vulnerabilities: list, target_url: str) -> str:
    """
    Generate a SARIF 2.1.0 JSON string from a list of vulnerability dicts.

    Convenience wrapper around :func:`generate_sarif` that returns a
    pretty-printed JSON string ready for file writing or API responses.
    """
    sarif = generate_sarif(vulnerabilities, target_url)
    return json.dumps(sarif, indent=2, ensure_ascii=False)
