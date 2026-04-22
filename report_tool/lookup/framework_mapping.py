"""Security framework mappings for vulnerability lookup.

Provides static CWE-based mappings to:
  - NIST SP 800-53 Rev 5 controls
  - PCI-DSS v4.0 requirements
  - OWASP Testing Guide (WSTG) v4.2 test references (expanded)
  - SANS/CWE Top 25 Most Dangerous Software Weaknesses (2023)
  - OWASP Top 10 2021 categories
  - OWASP API Security Top 10 2023 categories
  - ISO/IEC 27001:2022 Annex A controls

Public entries:
  get_frameworks(cwe_id) -> dict   — all framework data for one CWE
  get_sans_rank(cwe_id) -> int | None
  is_owasp_top10(cwe_id) -> bool
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# SANS/CWE Top 25 Most Dangerous Software Weaknesses 2023
# rank → CWE
# ---------------------------------------------------------------------------
_SANS_TOP25: dict[str, int] = {
    "CWE-787": 1,   # Out-of-bounds Write
    "CWE-79": 2,    # XSS
    "CWE-89": 3,    # SQL Injection
    "CWE-416": 4,   # Use After Free
    "CWE-78": 5,    # OS Command Injection
    "CWE-20": 6,    # Improper Input Validation
    "CWE-125": 7,   # Out-of-bounds Read
    "CWE-22": 8,    # Path Traversal
    "CWE-352": 9,   # CSRF
    "CWE-434": 10,  # Unrestricted File Upload
    "CWE-862": 11,  # Missing Authorization
    "CWE-476": 12,  # NULL Pointer Dereference
    "CWE-287": 13,  # Improper Authentication
    "CWE-190": 14,  # Integer Overflow
    "CWE-502": 15,  # Deserialization of Untrusted Data
    "CWE-77": 16,   # Command Injection
    "CWE-119": 17,  # Buffer Overflow
    "CWE-798": 18,  # Hard-coded Credentials
    "CWE-918": 19,  # SSRF
    "CWE-306": 20,  # Missing Authentication for Critical Function
    "CWE-362": 21,  # Race Condition
    "CWE-269": 22,  # Improper Privilege Management
    "CWE-94": 23,   # Code Injection
    "CWE-863": 24,  # Incorrect Authorization
    "CWE-276": 25,  # Incorrect Default Permissions
}

# ---------------------------------------------------------------------------
# OWASP Top 10 2021
# ---------------------------------------------------------------------------
_OWASP_TOP10: dict[str, str] = {
    "CWE-22": "A01:2021 - Broken Access Control",
    "CWE-284": "A01:2021 - Broken Access Control",
    "CWE-285": "A01:2021 - Broken Access Control",
    "CWE-639": "A01:2021 - Broken Access Control",
    "CWE-732": "A01:2021 - Broken Access Control",
    "CWE-862": "A01:2021 - Broken Access Control",
    "CWE-863": "A01:2021 - Broken Access Control",
    "CWE-200": "A01:2021 - Broken Access Control",
    "CWE-311": "A02:2021 - Cryptographic Failures",
    "CWE-312": "A02:2021 - Cryptographic Failures",
    "CWE-319": "A02:2021 - Cryptographic Failures",
    "CWE-326": "A02:2021 - Cryptographic Failures",
    "CWE-327": "A02:2021 - Cryptographic Failures",
    "CWE-328": "A02:2021 - Cryptographic Failures",
    "CWE-330": "A02:2021 - Cryptographic Failures",
    "CWE-20": "A03:2021 - Injection",
    "CWE-74": "A03:2021 - Injection",
    "CWE-77": "A03:2021 - Injection",
    "CWE-78": "A03:2021 - Injection",
    "CWE-79": "A03:2021 - Injection",
    "CWE-89": "A03:2021 - Injection",
    "CWE-90": "A03:2021 - Injection",
    "CWE-94": "A03:2021 - Injection",
    "CWE-643": "A03:2021 - Injection",
    "CWE-917": "A03:2021 - Injection",
    "CWE-1333": "A04:2021 - Insecure Design",
    "CWE-209": "A05:2021 - Security Misconfiguration",
    "CWE-611": "A05:2021 - Security Misconfiguration",
    "CWE-614": "A05:2021 - Security Misconfiguration",
    "CWE-1004": "A05:2021 - Security Misconfiguration",
    "CWE-937": "A06:2021 - Vulnerable and Outdated Components",
    "CWE-1035": "A06:2021 - Vulnerable and Outdated Components",
    "CWE-1104": "A06:2021 - Vulnerable and Outdated Components",
    "CWE-287": "A07:2021 - Identification and Authentication Failures",
    "CWE-295": "A07:2021 - Identification and Authentication Failures",
    "CWE-297": "A07:2021 - Identification and Authentication Failures",
    "CWE-306": "A07:2021 - Identification and Authentication Failures",
    "CWE-521": "A07:2021 - Identification and Authentication Failures",
    "CWE-522": "A07:2021 - Identification and Authentication Failures",
    "CWE-613": "A07:2021 - Identification and Authentication Failures",
    "CWE-620": "A07:2021 - Identification and Authentication Failures",
    "CWE-798": "A07:2021 - Identification and Authentication Failures",
    "CWE-502": "A08:2021 - Software and Data Integrity Failures",
    "CWE-494": "A08:2021 - Software and Data Integrity Failures",
    "CWE-829": "A08:2021 - Software and Data Integrity Failures",
    "CWE-778": "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-918": "A10:2021 - Server-Side Request Forgery",
    "CWE-352": "A01:2021 - Broken Access Control",  # CSRF also fits BAC
}

# ---------------------------------------------------------------------------
# NIST SP 800-53 Rev 5 — primary control family per CWE
# ---------------------------------------------------------------------------
_NIST_800_53: dict[str, list[str]] = {
    "CWE-79": ["SI-10 Information Input Validation", "SC-28 Protection of Information at Rest"],
    "CWE-89": ["SI-10 Information Input Validation", "AC-3 Access Enforcement"],
    "CWE-22": ["AC-3 Access Enforcement", "SI-10 Information Input Validation"],
    "CWE-78": ["SI-10 Information Input Validation", "CM-6 Configuration Settings"],
    "CWE-94": ["SI-10 Information Input Validation", "CM-7 Least Functionality"],
    "CWE-287": ["IA-2 Identification and Authentication", "IA-5 Authenticator Management"],
    "CWE-306": ["IA-2 Identification and Authentication", "AC-3 Access Enforcement"],
    "CWE-798": ["IA-5 Authenticator Management", "SC-28 Protection of Information at Rest"],
    "CWE-20": ["SI-10 Information Input Validation"],
    "CWE-200": ["AC-3 Access Enforcement", "AC-4 Information Flow Enforcement"],
    "CWE-521": ["IA-5 Authenticator Management"],
    "CWE-311": ["SC-28 Protection of Information at Rest", "SC-8 Transmission Confidentiality and Integrity"],
    "CWE-327": ["SC-13 Cryptographic Protection"],
    "CWE-502": ["SI-10 Information Input Validation", "CM-7 Least Functionality"],
    "CWE-352": ["SC-23 Session Authenticity", "SI-10 Information Input Validation"],
    "CWE-611": ["SI-10 Information Input Validation", "CM-6 Configuration Settings"],
    "CWE-918": ["SC-7 Boundary Protection", "AC-4 Information Flow Enforcement"],
    "CWE-1104": ["SA-22 Unsupported System Components", "RA-5 Vulnerability Monitoring and Scanning"],
    "CWE-937": ["SA-22 Unsupported System Components", "RA-5 Vulnerability Monitoring and Scanning"],
    "CWE-295": ["SC-8 Transmission Confidentiality and Integrity", "SC-13 Cryptographic Protection"],
    "CWE-732": ["AC-3 Access Enforcement", "AC-6 Least Privilege"],
    "CWE-862": ["AC-3 Access Enforcement", "AC-6 Least Privilege"],
    "CWE-863": ["AC-3 Access Enforcement", "AC-6 Least Privilege"],
    "CWE-434": ["SI-10 Information Input Validation", "CM-7 Least Functionality"],
    "CWE-601": ["SI-10 Information Input Validation", "SC-23 Session Authenticity"],
    "CWE-400": ["SC-5 Denial of Service Protection", "SI-10 Information Input Validation"],
}

# ---------------------------------------------------------------------------
# PCI-DSS v4.0 — primary requirements per CWE
# ---------------------------------------------------------------------------
_PCI_DSS: dict[str, list[str]] = {
    "CWE-79": ["Req 6.2.4 - Software attack prevention", "Req 6.4.1 - Public-facing web application protection"],
    "CWE-89": ["Req 6.2.4 - Software attack prevention", "Req 6.3.2 - Inventory of bespoke software"],
    "CWE-22": ["Req 6.2.4 - Software attack prevention"],
    "CWE-78": ["Req 6.2.4 - Software attack prevention", "Req 2.2.1 - Configuration standards"],
    "CWE-94": ["Req 6.2.4 - Software attack prevention"],
    "CWE-287": ["Req 8.3 - User authentication", "Req 8.4 - MFA"],
    "CWE-306": ["Req 8.3 - User authentication"],
    "CWE-798": ["Req 8.3.6 - Password complexity", "Req 6.3.3 - Security patches"],
    "CWE-311": ["Req 4.2 - Encrypt PAN in transit", "Req 3.5 - Protect PAN at rest"],
    "CWE-327": ["Req 4.2 - Encrypt PAN in transit", "Req 3.5 - Protect PAN at rest"],
    "CWE-352": ["Req 6.2.4 - Software attack prevention"],
    "CWE-502": ["Req 6.2.4 - Software attack prevention"],
    "CWE-521": ["Req 8.3.6 - Password complexity"],
    "CWE-611": ["Req 6.2.4 - Software attack prevention"],
    "CWE-918": ["Req 6.2.4 - Software attack prevention", "Req 1.3 - Network access controls"],
    "CWE-1104": ["Req 6.3.3 - Security patches and updates", "Req 12.3.3 - Cryptographic cipher suites review"],
    "CWE-937": ["Req 6.3.3 - Security patches and updates"],
    "CWE-295": ["Req 4.2 - Encrypt PAN in transit", "Req 4.2.1 - Strong cryptography"],
    "CWE-200": ["Req 3.3 - Sensitive authentication data protection", "Req 7.2 - Access control systems"],
    "CWE-434": ["Req 6.2.4 - Software attack prevention"],
    "CWE-732": ["Req 7.2 - Access control systems", "Req 7.3 - Least privilege"],
    "CWE-862": ["Req 7.2 - Access control systems", "Req 7.3 - Least privilege"],
}

# ---------------------------------------------------------------------------
# OWASP WSTG v4.2 — test reference per CWE
# ---------------------------------------------------------------------------
_OWASP_WSTG: dict[str, list[str]] = {
    # Injection (INPV)
    "CWE-79": ["WSTG-INPV-01: Testing for Reflected XSS", "WSTG-INPV-02: Testing for Stored XSS", "WSTG-CLNT-01: DOM-Based XSS"],
    "CWE-89": ["WSTG-INPV-05: Testing for SQL Injection"],
    "CWE-22": ["WSTG-INPV-13: Testing for Path Traversal", "WSTG-ATHZ-01: Testing Directory Traversal / File Include"],
    "CWE-78": ["WSTG-INPV-12: Testing for Command Injection"],
    "CWE-77": ["WSTG-INPV-12: Testing for Command Injection"],
    "CWE-94": ["WSTG-INPV-11: Testing for Code Injection", "WSTG-INPV-18: Testing for Server-Side Template Injection"],
    "CWE-90": ["WSTG-INPV-06: Testing for LDAP Injection"],
    "CWE-91": ["WSTG-INPV-07: Testing for XML Injection"],
    "CWE-643": ["WSTG-INPV-09: Testing for XPath Injection"],
    "CWE-74": ["WSTG-INPV-14: Testing for HTTP Parameter Pollution"],
    "CWE-113": ["WSTG-INPV-15: Testing for HTTP Splitting/Smuggling"],
    "CWE-444": ["WSTG-INPV-15: Testing for HTTP Splitting/Smuggling", "WSTG-INPV-16: Testing for HTTP Incoming Requests"],
    "CWE-917": ["WSTG-INPV-18: Testing for Server-Side Template Injection"],
    "CWE-1336": ["WSTG-INPV-18: Testing for Server-Side Template Injection"],
    "CWE-611": ["WSTG-INPV-07: Testing for XML Injection"],
    "CWE-776": ["WSTG-INPV-07: Testing for XML Injection"],
    "CWE-918": ["WSTG-INPV-19: Testing for Server-Side Request Forgery"],
    "CWE-20": ["WSTG-INPV-01: Testing for Reflected XSS", "WSTG-INPV-12: Testing for Command Injection"],
    "CWE-502": ["WSTG-INPV-11: Testing for Code Injection"],

    # Authentication (ATHN)
    "CWE-287": ["WSTG-ATHN-01: Testing for Credentials Transported over an Encrypted Channel", "WSTG-ATHN-06: Testing for Browser Cache Weaknesses"],
    "CWE-306": ["WSTG-ATHN-02: Testing for Default Credentials", "WSTG-ATHN-03: Testing for Weak Lockout Mechanism"],
    "CWE-307": ["WSTG-ATHN-03: Testing for Weak Lockout Mechanism"],
    "CWE-798": ["WSTG-ATHN-02: Testing for Default Credentials", "WSTG-CONF-06: Testing for HTTP Methods"],
    "CWE-521": ["WSTG-ATHN-07: Testing for Weak Password Policy"],
    "CWE-620": ["WSTG-ATHN-09: Testing for Weak Password Change / Reset"],
    "CWE-640": ["WSTG-ATHN-09: Testing for Weak Password Change / Reset"],
    "CWE-522": ["WSTG-ATHN-01: Credentials over Encrypted Channel", "WSTG-ATHN-06: Browser Cache Weaknesses"],
    "CWE-549": ["WSTG-ATHN-05: Testing for Vulnerable Remember Password"],
    "CWE-308": ["WSTG-ATHN-11: Testing Multi-Factor Authentication (MFA)"],

    # Authorization (ATHZ)
    "CWE-285": ["WSTG-ATHZ-02: Testing for Bypassing Authorization Schema"],
    "CWE-284": ["WSTG-ATHZ-02: Testing for Bypassing Authorization Schema"],
    "CWE-639": ["WSTG-ATHZ-04: Testing for Insecure Direct Object References"],
    "CWE-862": ["WSTG-ATHZ-01: Testing Directory Traversal File Include", "WSTG-ATHZ-02: Testing for Bypassing Authorization Schema"],
    "CWE-863": ["WSTG-ATHZ-02: Testing for Bypassing Authorization Schema", "WSTG-ATHZ-03: Testing for Privilege Escalation"],
    "CWE-269": ["WSTG-ATHZ-03: Testing for Privilege Escalation"],
    "CWE-732": ["WSTG-ATHZ-02: Testing for Bypassing Authorization Schema", "WSTG-CONF-08: Testing for File Permission"],

    # Session Management (SESS)
    "CWE-352": ["WSTG-SESS-05: Testing for Cross Site Request Forgery"],
    "CWE-384": ["WSTG-SESS-03: Testing for Session Fixation"],
    "CWE-613": ["WSTG-SESS-07: Testing Session Timeout"],
    "CWE-614": ["WSTG-SESS-02: Testing for Cookies Attributes"],
    "CWE-1004": ["WSTG-SESS-02: Testing for Cookies Attributes"],
    "CWE-539": ["WSTG-SESS-04: Testing for Exposed Session Variables"],

    # Cryptography (CRYP)
    "CWE-311": ["WSTG-CRYP-01: Testing for Weak Transport Layer Security"],
    "CWE-312": ["WSTG-CRYP-03: Testing for Sensitive Information Sent via Unencrypted Channels"],
    "CWE-319": ["WSTG-CRYP-03: Testing for Sensitive Information Sent via Unencrypted Channels"],
    "CWE-326": ["WSTG-CRYP-04: Testing for Weak Encryption"],
    "CWE-327": ["WSTG-CRYP-01: Testing for Weak TLS", "WSTG-CRYP-04: Testing for Weak Encryption"],
    "CWE-328": ["WSTG-CRYP-04: Testing for Weak Encryption"],
    "CWE-330": ["WSTG-CRYP-04: Testing for Weak Encryption"],
    "CWE-295": ["WSTG-CRYP-01: Testing for Weak Transport Layer Security"],
    "CWE-297": ["WSTG-CRYP-01: Testing for Weak Transport Layer Security"],
    "CWE-798_crypto": ["WSTG-CRYP-04: Testing for Weak Encryption"],

    # Information Gathering (INFO)
    "CWE-200": ["WSTG-INFO-05: Review Webpage Content for Information Leakage", "WSTG-ERRH-01: Testing for Improper Error Handling"],
    "CWE-209": ["WSTG-ERRH-01: Testing for Improper Error Handling"],
    "CWE-548": ["WSTG-CONF-04: Review Old Backup and Unreferenced Files"],
    "CWE-538": ["WSTG-INFO-05: Review Webpage Content for Information Leakage"],

    # Configuration (CONF)
    "CWE-16": ["WSTG-CONF-01: Testing Network / Infrastructure Configuration"],
    "CWE-1104": ["WSTG-CONF-02: Testing Application Platform Configuration"],
    "CWE-937": ["WSTG-CONF-02: Testing Application Platform Configuration"],
    "CWE-1035": ["WSTG-CONF-02: Testing Application Platform Configuration"],
    "CWE-525": ["WSTG-CONF-03: Testing File Extensions Handling for Sensitive Information"],
    "CWE-538_conf": ["WSTG-CONF-04: Review Old Backup and Unreferenced Files"],
    "CWE-16_conf": ["WSTG-CONF-05: Enumerate Infrastructure and Application Admin Interfaces"],
    "CWE-749": ["WSTG-CONF-06: Testing HTTP Methods"],
    "CWE-346": ["WSTG-CONF-07: Testing HTTP Strict Transport Security"],
    "CWE-942": ["WSTG-CONF-08: Testing RIA Cross Domain Policy"],

    # Error Handling (ERRH)
    "CWE-388": ["WSTG-ERRH-01: Testing for Improper Error Handling"],
    "CWE-248": ["WSTG-ERRH-02: Testing for Stack Traces"],

    # Client-side (CLNT)
    "CWE-601": ["WSTG-CLNT-04: Testing for Client-side URL Redirect"],
    "CWE-451": ["WSTG-CLNT-11: Testing Web Messaging"],
    "CWE-942_cors": ["WSTG-CLNT-07: Testing Cross Origin Resource Sharing"],
    "CWE-1021": ["WSTG-CLNT-09: Testing for Clickjacking"],
    "CWE-79_client": ["WSTG-CLNT-01: DOM-Based XSS"],

    # Business Logic (BUSL)
    "CWE-434": ["WSTG-BUSL-09: Testing for Upload of Malicious Files", "WSTG-BUSL-08: Testing Upload of Unexpected File Types"],
    "CWE-840": ["WSTG-BUSL-01: Testing for Business Logic Data Validation"],
    "CWE-837": ["WSTG-BUSL-03: Testing for Integrity Checks"],

    # DoS / Resource
    "CWE-400": ["WSTG-BUSL-04: Testing for Process Timing"],
    "CWE-1333": ["WSTG-INPV-01: Testing for Reflected XSS"],  # ReDoS via input — nearest WSTG
}

# ---------------------------------------------------------------------------
# OWASP API Security Top 10 2023
# ---------------------------------------------------------------------------
_OWASP_API_TOP10: dict[str, str] = {
    "CWE-639": "API1:2023 - Broken Object Level Authorization",
    "CWE-284": "API1:2023 - Broken Object Level Authorization",
    "CWE-285": "API1:2023 - Broken Object Level Authorization",
    "CWE-287": "API2:2023 - Broken Authentication",
    "CWE-306": "API2:2023 - Broken Authentication",
    "CWE-307": "API2:2023 - Broken Authentication",
    "CWE-798": "API2:2023 - Broken Authentication",
    "CWE-521": "API2:2023 - Broken Authentication",
    "CWE-915": "API3:2023 - Broken Object Property Level Authorization",
    "CWE-213": "API3:2023 - Broken Object Property Level Authorization",
    "CWE-400": "API4:2023 - Unrestricted Resource Consumption",
    "CWE-770": "API4:2023 - Unrestricted Resource Consumption",
    "CWE-863": "API5:2023 - Broken Function Level Authorization",
    "CWE-862": "API5:2023 - Broken Function Level Authorization",
    "CWE-841": "API6:2023 - Unrestricted Access to Sensitive Business Flows",
    "CWE-918": "API7:2023 - Server Side Request Forgery",
    "CWE-16": "API8:2023 - Security Misconfiguration",
    "CWE-209": "API8:2023 - Security Misconfiguration",
    "CWE-1004": "API8:2023 - Security Misconfiguration",
    "CWE-614": "API8:2023 - Security Misconfiguration",
    "CWE-942": "API8:2023 - Security Misconfiguration",
    "CWE-1059": "API9:2023 - Improper Inventory Management",
    "CWE-1053": "API9:2023 - Improper Inventory Management",
    "CWE-829": "API10:2023 - Unsafe Consumption of APIs",
    "CWE-494": "API10:2023 - Unsafe Consumption of APIs",
    "CWE-20": "API10:2023 - Unsafe Consumption of APIs",
}

# ---------------------------------------------------------------------------
# ISO/IEC 27001:2022 Annex A controls per CWE
# ---------------------------------------------------------------------------
_ISO_27001: dict[str, list[str]] = {
    "CWE-79": ["A.8.28 - Secure coding", "A.8.9 - Configuration management"],
    "CWE-89": ["A.8.28 - Secure coding", "A.8.9 - Configuration management"],
    "CWE-22": ["A.8.28 - Secure coding", "A.8.3 - Information access restriction"],
    "CWE-78": ["A.8.28 - Secure coding", "A.8.9 - Configuration management"],
    "CWE-287": ["A.8.5 - Secure authentication", "A.8.2 - Privileged access rights"],
    "CWE-306": ["A.8.5 - Secure authentication", "A.8.3 - Information access restriction"],
    "CWE-798": ["A.8.5 - Secure authentication", "A.5.17 - Authentication information"],
    "CWE-311": ["A.8.24 - Use of cryptography", "A.8.16 - Monitoring activities"],
    "CWE-327": ["A.8.24 - Use of cryptography"],
    "CWE-352": ["A.8.28 - Secure coding", "A.8.20 - Networks security"],
    "CWE-502": ["A.8.28 - Secure coding"],
    "CWE-521": ["A.5.17 - Authentication information", "A.8.5 - Secure authentication"],
    "CWE-918": ["A.8.20 - Networks security", "A.8.22 - Segregation of networks"],
    "CWE-1104": ["A.8.8 - Management of technical vulnerabilities", "A.8.30 - Outsourced development"],
    "CWE-937": ["A.8.8 - Management of technical vulnerabilities"],
    "CWE-200": ["A.8.3 - Information access restriction", "A.8.12 - Data leakage prevention"],
    "CWE-434": ["A.8.28 - Secure coding", "A.8.9 - Configuration management"],
    "CWE-732": ["A.8.3 - Information access restriction", "A.8.2 - Privileged access rights"],
    "CWE-862": ["A.8.3 - Information access restriction", "A.8.2 - Privileged access rights"],
}


def _enrich_nist_from_catalog(items: list[str]) -> list[str]:
    """Replace short 'AC-3 Access Enforcement' entries with catalog-authoritative
    titles when the NIST DB has been ingested. Falls back silently otherwise."""
    try:
        from report_tool.lookup import nist_catalog
    except ImportError:
        return items
    try:
        if nist_catalog.count_entries() == 0:
            return items
    except Exception:
        return items
    out: list[str] = []
    for item in items:
        ctrl_id = item.split(" ", 1)[0].upper()
        rec = None
        try:
            rec = nist_catalog.get_control(ctrl_id)
        except Exception:
            rec = None
        if rec and rec.get("title"):
            out.append(f"{ctrl_id} {rec['title']}")
        else:
            out.append(item)
    return out


def get_frameworks(cwe_id: str) -> dict:
    """Return all framework mappings for a CWE as a single dict."""
    if not cwe_id:
        return {}
    norm = cwe_id.strip().upper()
    if not norm.startswith("CWE-"):
        norm = f"CWE-{norm}"
    return {
        "sans_top25_rank": _SANS_TOP25.get(norm),
        "owasp_top10": _OWASP_TOP10.get(norm),
        "owasp_api_top10": _OWASP_API_TOP10.get(norm),
        "nist_800_53": _enrich_nist_from_catalog(_NIST_800_53.get(norm, [])),
        "pci_dss": _PCI_DSS.get(norm, []),
        "owasp_wstg": _OWASP_WSTG.get(norm, []),
        "iso_27001": _ISO_27001.get(norm, []),
    }


def get_sans_rank(cwe_id: str) -> int | None:
    norm = cwe_id.strip().upper()
    if not norm.startswith("CWE-"):
        norm = f"CWE-{norm}"
    return _SANS_TOP25.get(norm)


def is_owasp_top10(cwe_id: str) -> bool:
    norm = cwe_id.strip().upper()
    if not norm.startswith("CWE-"):
        norm = f"CWE-{norm}"
    return norm in _OWASP_TOP10


def get_merged_frameworks(cwe_ids: list[str]) -> dict:
    """Merge framework data across multiple CWEs (deduplicated)."""
    merged: dict = {
        "sans_top25_rank": None,
        "owasp_top10": None,
        "owasp_api_top10": None,
        "nist_800_53": [],
        "pci_dss": [],
        "owasp_wstg": [],
        "iso_27001": [],
    }
    for cid in cwe_ids:
        fw = get_frameworks(cid)
        rank = fw.get("sans_top25_rank")
        if rank and (merged["sans_top25_rank"] is None or rank < merged["sans_top25_rank"]):
            merged["sans_top25_rank"] = rank
        if fw.get("owasp_top10") and not merged["owasp_top10"]:
            merged["owasp_top10"] = fw["owasp_top10"]
        if fw.get("owasp_api_top10") and not merged["owasp_api_top10"]:
            merged["owasp_api_top10"] = fw["owasp_api_top10"]
        for key in ("nist_800_53", "pci_dss", "owasp_wstg", "iso_27001"):
            for item in fw.get(key, []):
                if item not in merged[key]:
                    merged[key].append(item)
    return merged
