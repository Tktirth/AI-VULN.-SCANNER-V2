# Contributing to AI Vulnerability Scanner V2

Thank you for considering contributing to this project! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](../../issues)
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version)

### Suggesting Features

1. Open an issue with the `enhancement` label
2. Describe the feature and its use case
3. Provide examples if possible

### Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Follow the coding standards below
4. Write tests for new functionality
5. Commit with clear messages (see Commit Convention below)
6. Push and open a Pull Request

## Coding Standards

- **Style**: Follow PEP 8 for Python code
- **Type Hints**: Use type annotations on all function signatures
- **Docstrings**: Required on all classes and public functions
- **Error Handling**: Detectors must never raise — always return partial results
- **Logging**: Use `logger.debug()` for operational errors, `logger.warning()` for rate limits

### Detector Module Pattern

All vulnerability detectors follow this pattern:

```python
def detect_xxx(target_url: str, request_manager, scanned_urls: list) -> List[Dict[str, Any]]:
    """Detect [vulnerability type] across scanned URLs."""
    vulns = []
    try:
        # Detection logic here
        pass
    except Exception as e:
        logger.debug(f"Detection error: {e}")
    return vulns
```

### Finding Dict Format

All findings must include:

```python
{
    "type": str,           # e.g. "Cross-Site Scripting (XSS)"
    "subtype": str,        # e.g. "Reflected XSS"
    "severity": str,       # "Critical" | "High" | "Medium" | "Low"
    "cvss_score": float,   # 0.0 - 10.0
    "cwe_id": str,         # e.g. "CWE-79"
    "url": str,
    "parameter": str,
    "method": str,         # "GET" | "POST"
    "payload": str,
    "evidence": str,
    "description": str,
    "remediation": str,
}
```

## Commit Convention

Use conventional commits:

```
feat: add IP leakage detector module
fix: resolve CDN detection false positive for Akamai
docs: update README with recon module usage
refactor: extract CDN IP ranges to shared constants
```

## Architecture Overview

```
scanner_engine.py          ← Orchestrator (phases 0-8)
├── recon/                 ← Phase 0: IP intelligence
│   ├── ip_resolver.py     ← DNS + CDN + ASN
│   └── cdn_bypass.py      ← Origin IP discovery
├── crawler.py             ← Phase 2: BFS web crawler
├── detectors/             ← Phases 3-7: Vulnerability detectors
│   ├── header_detector.py
│   ├── xss_detector.py
│   ├── sql_detector.py
│   ├── redirect_detector.py
│   ├── directory_detector.py
│   ├── idor_detector.py
│   └── ip_leakage.py
├── ai/                    ← Phase 8: ML classification
│   └── vulnerability_ai.py
└── reports/               ← JSON report generation
    └── report_generator.py
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
