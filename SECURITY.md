# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| 1.x     | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in this tool, please report it responsibly.

**DO NOT** create a public GitHub issue for security vulnerabilities.

### How to Report

1. **Email**: Send details to the repository maintainer via GitHub private security advisory
2. **GitHub Security Advisories**: Use the [Security tab](../../security/advisories/new) to create a private advisory

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgement**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Resolution**: Dependent on severity (Critical: ASAP, High: 7 days, Medium: 30 days)

## Legal & Ethical Use

This tool is designed for **authorized security testing only**. Users must:

1. **Only scan targets they own** or have explicit written permission to test
2. **Comply with all applicable laws** in their jurisdiction
3. **Not use this tool** for unauthorized access, data theft, or malicious purposes
4. **Follow responsible disclosure** practices for any vulnerabilities found

Unauthorized scanning of systems you do not own is **illegal** under the Computer Fraud and Abuse Act (CFAA) and equivalent legislation worldwide.

## Scope

The following are in-scope for security reports:

- Vulnerabilities in the scanner engine itself
- API key exposure risks
- SSRF bypass in scanning components
- Data leakage from scan results
- Authentication bypass in the tool's auth module

The following are **out of scope**:

- Vulnerabilities found in targets being scanned (these should be reported to the target's owner)
- Denial of service against external APIs used by the scanner
