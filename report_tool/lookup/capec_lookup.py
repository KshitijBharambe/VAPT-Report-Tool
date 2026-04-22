"""CAPEC (Common Attack Pattern Enumeration and Classification) lookup.

Static snapshot mapping CWE IDs to CAPEC attack patterns.
Covers the most common VAPT-relevant attack patterns per MITRE CAPEC 3.9.

Public entry: fetch_capec_for_cwe(cwe_id) -> list[dict]
Returns list of {id, name, likelihood, severity, description} or [].
"""

from __future__ import annotations

# CWE → list of CAPEC entries (id, name, likelihood, typical_severity)
# Likelihood: High / Medium / Low
# Severity: Very High / High / Medium / Low
_CWE_TO_CAPEC: dict[str, list[dict]] = {
    "CWE-79": [
        {"id": "CAPEC-86", "name": "XSS via HTTP Request Headers", "likelihood": "High", "severity": "High"},
        {"id": "CAPEC-198", "name": "XSS via HTTP Query Strings", "likelihood": "High", "severity": "High"},
        {"id": "CAPEC-588", "name": "DOM-Based XSS", "likelihood": "High", "severity": "High"},
    ],
    "CWE-89": [
        {"id": "CAPEC-66", "name": "SQL Injection", "likelihood": "High", "severity": "High"},
        {"id": "CAPEC-7", "name": "Blind SQL Injection", "likelihood": "Medium", "severity": "High"},
        {"id": "CAPEC-110", "name": "SQL Injection through SOAP Parameter Tampering", "likelihood": "Medium", "severity": "High"},
    ],
    "CWE-22": [
        {"id": "CAPEC-126", "name": "Path Traversal", "likelihood": "High", "severity": "High"},
        {"id": "CAPEC-64", "name": "Using Slashes and URL Encoding Combined to Bypass Validation Logic", "likelihood": "Medium", "severity": "Medium"},
    ],
    "CWE-78": [
        {"id": "CAPEC-88", "name": "OS Command Injection", "likelihood": "High", "severity": "Very High"},
        {"id": "CAPEC-183", "name": "IMAP/SMTP Command Injection", "likelihood": "Medium", "severity": "High"},
    ],
    "CWE-94": [
        {"id": "CAPEC-242", "name": "Code Injection", "likelihood": "High", "severity": "High"},
        {"id": "CAPEC-35", "name": "Leverage Executable Code in Non-Executable Files", "likelihood": "Medium", "severity": "High"},
    ],
    "CWE-287": [
        {"id": "CAPEC-114", "name": "Authentication Abuse", "likelihood": "Medium", "severity": "High"},
        {"id": "CAPEC-194", "name": "Fake the Source of Data", "likelihood": "Medium", "severity": "Medium"},
        {"id": "CAPEC-196", "name": "Session Credential Falsification through Forging", "likelihood": "Medium", "severity": "High"},
    ],
    "CWE-306": [
        {"id": "CAPEC-36", "name": "Using Unpublished Interfaces or Functionality", "likelihood": "Medium", "severity": "High"},
        {"id": "CAPEC-1", "name": "Accessing Functionality Not Properly Constrained by ACLs", "likelihood": "High", "severity": "High"},
    ],
    "CWE-352": [
        {"id": "CAPEC-62", "name": "Cross-Site Request Forgery", "likelihood": "Medium", "severity": "High"},
        {"id": "CAPEC-111", "name": "JSON Hijacking", "likelihood": "Medium", "severity": "High"},
    ],
    "CWE-611": [
        {"id": "CAPEC-221", "name": "DTD Injection", "likelihood": "Medium", "severity": "High"},
        {"id": "CAPEC-228", "name": "DTD Injection via DocType Declaration", "likelihood": "Medium", "severity": "High"},
    ],
    "CWE-918": [
        {"id": "CAPEC-664", "name": "Server Side Request Forgery", "likelihood": "Medium", "severity": "High"},
    ],
    "CWE-200": [
        {"id": "CAPEC-116", "name": "Excavation", "likelihood": "High", "severity": "Medium"},
        {"id": "CAPEC-118", "name": "Collect and Analyze Information", "likelihood": "High", "severity": "Medium"},
        {"id": "CAPEC-169", "name": "Footprinting", "likelihood": "High", "severity": "Low"},
    ],
    "CWE-311": [
        {"id": "CAPEC-157", "name": "Sniffing Attacks", "likelihood": "Medium", "severity": "High"},
        {"id": "CAPEC-609", "name": "Cellular Traffic Interception", "likelihood": "Low", "severity": "High"},
    ],
    "CWE-327": [
        {"id": "CAPEC-97", "name": "Cryptanalysis of Cellular Phone Communication", "likelihood": "Low", "severity": "High"},
        {"id": "CAPEC-20", "name": "Encryption Brute Forcing", "likelihood": "Medium", "severity": "Medium"},
    ],
    "CWE-798": [
        {"id": "CAPEC-70", "name": "Try Common or Default Usernames and Passwords", "likelihood": "High", "severity": "Medium"},
        {"id": "CAPEC-191", "name": "Read Sensitive Constants Within an Executable", "likelihood": "Medium", "severity": "Medium"},
    ],
    "CWE-502": [
        {"id": "CAPEC-586", "name": "Object Injection", "likelihood": "Medium", "severity": "High"},
        {"id": "CAPEC-441", "name": "Malicious Logic Insertion via Dependency", "likelihood": "Low", "severity": "High"},
    ],
    "CWE-434": [
        {"id": "CAPEC-1", "name": "Accessing Functionality Not Properly Constrained by ACLs", "likelihood": "Medium", "severity": "High"},
        {"id": "CAPEC-17", "name": "Using Malicious Files", "likelihood": "Medium", "severity": "High"},
    ],
    "CWE-20": [
        {"id": "CAPEC-28", "name": "Fuzzing for application mapping", "likelihood": "Medium", "severity": "Medium"},
        {"id": "CAPEC-153", "name": "Input Data Manipulation", "likelihood": "Medium", "severity": "Medium"},
    ],
    "CWE-521": [
        {"id": "CAPEC-70", "name": "Try Common or Default Usernames and Passwords", "likelihood": "High", "severity": "Medium"},
        {"id": "CAPEC-16", "name": "Dictionary-based Password Attack", "likelihood": "Medium", "severity": "Medium"},
        {"id": "CAPEC-49", "name": "Password Brute Forcing", "likelihood": "Medium", "severity": "Medium"},
    ],
    "CWE-1104": [
        {"id": "CAPEC-441", "name": "Malicious Logic Insertion via Dependency", "likelihood": "Medium", "severity": "High"},
        {"id": "CAPEC-538", "name": "Open-Source Library Manipulation", "likelihood": "Low", "severity": "High"},
    ],
    "CWE-937": [
        {"id": "CAPEC-441", "name": "Malicious Logic Insertion via Dependency", "likelihood": "Medium", "severity": "High"},
        {"id": "CAPEC-69", "name": "Target Programs with Elevated Privileges", "likelihood": "Medium", "severity": "High"},
    ],
    # Additional common VAPT CWEs
    "CWE-295": [
        {"id": "CAPEC-94", "name": "Adversary in the Middle (AiTM)", "likelihood": "Medium", "severity": "High"},
        {"id": "CAPEC-606", "name": "Weakening of Cellular Encryption", "likelihood": "Low", "severity": "High"},
    ],
    "CWE-601": [
        {"id": "CAPEC-194", "name": "Fake the Source of Data", "likelihood": "Medium", "severity": "Medium"},
        {"id": "CAPEC-698", "name": "Install Malicious Extension", "likelihood": "Low", "severity": "Medium"},
    ],
    "CWE-400": [
        {"id": "CAPEC-469", "name": "HTTP DoS", "likelihood": "Medium", "severity": "Medium"},
        {"id": "CAPEC-528", "name": "XML Flood", "likelihood": "Medium", "severity": "Medium"},
    ],
    "CWE-732": [
        {"id": "CAPEC-1", "name": "Accessing Functionality Not Properly Constrained by ACLs", "likelihood": "High", "severity": "High"},
        {"id": "CAPEC-122", "name": "Privilege Abuse", "likelihood": "Medium", "severity": "High"},
    ],
    "CWE-862": [
        {"id": "CAPEC-1", "name": "Accessing Functionality Not Properly Constrained by ACLs", "likelihood": "High", "severity": "High"},
        {"id": "CAPEC-122", "name": "Privilege Abuse", "likelihood": "Medium", "severity": "High"},
    ],
    "CWE-863": [
        {"id": "CAPEC-122", "name": "Privilege Abuse", "likelihood": "Medium", "severity": "High"},
        {"id": "CAPEC-1", "name": "Accessing Functionality Not Properly Constrained by ACLs", "likelihood": "High", "severity": "High"},
    ],
    "CWE-77": [
        {"id": "CAPEC-88", "name": "OS Command Injection", "likelihood": "High", "severity": "Very High"},
        {"id": "CAPEC-15", "name": "Command Delimiters", "likelihood": "Medium", "severity": "Medium"},
    ],
    "CWE-90": [
        {"id": "CAPEC-136", "name": "LDAP Injection", "likelihood": "Medium", "severity": "High"},
    ],
    "CWE-643": [
        {"id": "CAPEC-83", "name": "XPath Injection", "likelihood": "Medium", "severity": "High"},
    ],
    "CWE-918": [
        {"id": "CAPEC-664", "name": "Server Side Request Forgery", "likelihood": "Medium", "severity": "High"},
    ],
    "CWE-1333": [
        {"id": "CAPEC-492", "name": "Regular Expression Exponential Blowup", "likelihood": "Medium", "severity": "Medium"},
    ],
}


def _from_catalog(cwe_id: str) -> list[dict]:
    try:
        from report_tool.lookup import capec_catalog
    except ImportError:
        return []
    try:
        rows = capec_catalog.get_capecs_for_cwe(cwe_id)
    except Exception:
        return []
    out: list[dict] = []
    for r in rows:
        out.append(
            {
                "id": r.get("id", ""),
                "name": r.get("name", ""),
                "likelihood": r.get("likelihood", "") or "Unknown",
                "severity": r.get("severity", "") or "Unknown",
                "description": r.get("description", ""),
            }
        )
    return out


def fetch_capec_for_cwe(cwe_id: str) -> list[dict]:
    """Return CAPEC attack patterns linked to a CWE. Empty list on miss.

    Prefers full MITRE CAPEC SQLite catalog; falls back to static snapshot.
    """
    if not cwe_id:
        return []
    norm = cwe_id.strip().upper()
    if not norm.startswith("CWE-"):
        norm = f"CWE-{norm}"
    rows = _from_catalog(norm)
    if rows:
        return rows
    return list(_CWE_TO_CAPEC.get(norm, []))


def fetch_capec_for_cwes(cwe_ids: list[str]) -> list[dict]:
    """Return deduplicated CAPEC patterns for multiple CWEs."""
    seen: set[str] = set()
    results: list[dict] = []
    for cid in cwe_ids:
        for pattern in fetch_capec_for_cwe(cid):
            key = pattern.get("id", "")
            if key and key not in seen:
                seen.add(key)
                results.append(pattern)
    return results
