"""CWE lookup — static snapshot of common CWEs + MITRE XML fallback.

Public entry: fetch_cwe(cwe_id) -> dict | None
Returns {id, name, description, owasp_category, control_objective, control_name}.

Snapshot covers CWE Top 25 + common VAPT weaknesses. For misses, optionally
queries MITRE REST API (no key). Falls back to None; caller then uses cloud LLM.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_CACHE_DIR = Path.home() / ".cache" / "sqtk-tools" / "cwe"
_CWE_RE = re.compile(r"^CWE-\d{1,5}$", re.IGNORECASE)

# Hand-curated snapshot of high-traffic CWEs. Each entry supplies the
# control objective + control name template seen in handmade VAPT reports.
_SNAPSHOT: dict[str, dict] = {
    "CWE-79": {
        "name": "Cross-site Scripting",
        "description": "Improper neutralization of input during web page generation allows attackers to inject client-side scripts.",
        "owasp_category": "A03:2021 - Injection",
        "control_objective": "Ensure all user-supplied input rendered in web pages is contextually encoded and sanitized to prevent script injection.",
        "control_name": "Input Validation and Output Encoding",
    },
    "CWE-89": {
        "name": "SQL Injection",
        "description": "Improper neutralization of special elements in SQL commands permits attackers to manipulate database queries.",
        "owasp_category": "A03:2021 - Injection",
        "control_objective": "Ensure all database queries use parameterized statements and input validation to prevent SQL manipulation.",
        "control_name": "Parameterized Query Enforcement",
    },
    "CWE-22": {
        "name": "Path Traversal",
        "description": "Improper limitation of pathname to restricted directory enables attackers to access unauthorized files.",
        "owasp_category": "A01:2021 - Broken Access Control",
        "control_objective": "Ensure file path inputs are canonicalized and restricted to intended directories.",
        "control_name": "Path Canonicalization Control",
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "description": "The product does not prove or insufficiently proves that the claimed identity is correct.",
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "control_objective": "Ensure all sensitive operations require verified authentication with strong credential controls.",
        "control_name": "Authentication Control",
    },
    "CWE-306": {
        "name": "Missing Authentication for Critical Function",
        "description": "The product does not perform authentication for functionality that requires provable user identity.",
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "control_objective": "Ensure every critical function enforces authentication before execution.",
        "control_name": "Authentication Enforcement",
    },
    "CWE-798": {
        "name": "Use of Hard-coded Credentials",
        "description": "The product contains hard-coded credentials, simplifying attacker access to protected resources.",
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "control_objective": "Ensure credentials are sourced from a secure secrets store and never hardcoded.",
        "control_name": "Secrets Management Control",
    },
    "CWE-20": {
        "name": "Improper Input Validation",
        "description": "The product does not validate or incorrectly validates input that can affect the control flow or data flow.",
        "owasp_category": "A03:2021 - Injection",
        "control_objective": "Ensure all inputs are validated against expected types, lengths, and allowed values.",
        "control_name": "Input Validation Control",
    },
    "CWE-200": {
        "name": "Exposure of Sensitive Information",
        "description": "The product exposes sensitive information to an actor not explicitly authorized to have access.",
        "owasp_category": "A01:2021 - Broken Access Control",
        "control_objective": "Ensure sensitive data is restricted to authorized actors and not leaked through errors or responses.",
        "control_name": "Information Exposure Control",
    },
    "CWE-521": {
        "name": "Weak Password Requirements",
        "description": "The product does not require users to have strong passwords.",
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "control_objective": "Ensure password policies enforce sufficient complexity, length, and rotation.",
        "control_name": "Password Policy Control",
    },
    "CWE-311": {
        "name": "Missing Encryption of Sensitive Data",
        "description": "The product does not encrypt sensitive or critical information before storage or transmission.",
        "owasp_category": "A02:2021 - Cryptographic Failures",
        "control_objective": "Ensure sensitive data is encrypted at rest and in transit using approved algorithms.",
        "control_name": "Data Encryption Control",
    },
    "CWE-327": {
        "name": "Use of Broken or Risky Cryptographic Algorithm",
        "description": "The product uses a cryptographic algorithm that is insecure or has been broken.",
        "owasp_category": "A02:2021 - Cryptographic Failures",
        "control_objective": "Ensure cryptographic algorithms meet current standards (AES-256, SHA-256, TLS 1.2+).",
        "control_name": "Cryptographic Standards Control",
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "description": "The product deserializes untrusted data without sufficiently verifying the resulting data.",
        "owasp_category": "A08:2021 - Software and Data Integrity Failures",
        "control_objective": "Ensure deserialization accepts only signed or validated payloads from trusted sources.",
        "control_name": "Safe Deserialization Control",
    },
    "CWE-352": {
        "name": "Cross-Site Request Forgery",
        "description": "The web application does not verify that a request was intentionally provided by the user who submitted it.",
        "owasp_category": "A01:2021 - Broken Access Control",
        "control_objective": "Ensure state-changing requests require anti-CSRF tokens bound to the user session.",
        "control_name": "CSRF Protection Control",
    },
    "CWE-611": {
        "name": "XML External Entity Reference",
        "description": "The product processes XML that can reference external entities, leading to data disclosure or SSRF.",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "control_objective": "Ensure XML parsers disable external entity resolution and DTD processing.",
        "control_name": "XXE Prevention Control",
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery",
        "description": "The web server receives a URL or similar request from an upstream component and retrieves it without validation.",
        "owasp_category": "A10:2021 - Server-Side Request Forgery",
        "control_objective": "Ensure outbound HTTP requests use allow-lists for destinations and validate URL schemes.",
        "control_name": "SSRF Prevention Control",
    },
    "CWE-1104": {
        "name": "Use of Unmaintained Third Party Components",
        "description": "The product relies on third-party components that are no longer maintained.",
        "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
        "control_objective": "Ensure third-party components are actively maintained and updated against a tracked SBOM.",
        "control_name": "Component Lifecycle Control",
    },
    "CWE-937": {
        "name": "OWASP Top Ten - Known Vulnerable Components",
        "description": "The product includes a component with known vulnerabilities.",
        "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
        "control_objective": "Ensure that remote servers run the most updated version of the software, operating system, or applications.",
        "control_name": "Outdated Version Control",
    },
    "CWE-94": {
        "name": "Improper Control of Generation of Code",
        "description": "The product constructs all or part of a code segment using externally-influenced input.",
        "owasp_category": "A03:2021 - Injection",
        "control_objective": "Ensure that code generation does not incorporate untrusted input into executable segments.",
        "control_name": "Code Injection Prevention Control",
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "description": "The product constructs OS commands using externally-influenced input without proper neutralization.",
        "owasp_category": "A03:2021 - Injection",
        "control_objective": "Ensure OS command invocations use parameterized APIs and strict input validation.",
        "control_name": "Command Injection Prevention Control",
    },
    "CWE-434": {
        "name": "Unrestricted Upload of File with Dangerous Type",
        "description": "The product allows attackers to upload or transfer files of dangerous types.",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "control_objective": "Ensure uploaded files are validated by MIME, extension, and content inspection before acceptance.",
        "control_name": "File Upload Control",
    },
}


def _normalize(cwe_id: str) -> str | None:
    if not cwe_id:
        return None
    raw = cwe_id.strip().upper()
    if raw.isdigit():
        raw = f"CWE-{raw}"
    return raw if _CWE_RE.match(raw) else None


def _cache_path(cwe_id: str) -> Path:
    return _CACHE_DIR / f"{cwe_id}.json"


def _read_cache(cwe_id: str) -> dict | None:
    path = _cache_path(cwe_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _write_cache(cwe_id: str, data: dict) -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _cache_path(cwe_id).write_text(json.dumps(data, indent=2))
    except OSError:
        pass


def _from_catalog_db(norm: str) -> dict | None:
    """Merge full MITRE catalog entry with snapshot defaults (control_objective/name)."""
    try:
        from report_tool.lookup.cwe_catalog import get_cwe_from_db
    except ImportError:
        return None
    try:
        rec = get_cwe_from_db(norm)
    except Exception:
        return None
    if not rec:
        return None
    merged: dict = {"id": norm}
    snap = _SNAPSHOT.get(norm) or {}
    merged["name"] = rec.get("name") or snap.get("name", "")
    desc = rec.get("description") or ""
    ext = rec.get("extended_description") or ""
    merged["description"] = (desc + (" " + ext if ext else "")).strip() or snap.get(
        "description", ""
    )
    merged["owasp_category"] = snap.get("owasp_category", "")
    merged["control_objective"] = snap.get("control_objective", "")
    merged["control_name"] = snap.get("control_name", "")
    if rec.get("consequences"):
        merged["consequences"] = rec["consequences"]
    if rec.get("mitigations"):
        merged["mitigations"] = rec["mitigations"]
    if rec.get("detection_methods"):
        merged["detection_methods"] = rec["detection_methods"]
    if rec.get("refs"):
        merged["refs"] = rec["refs"]
    if rec.get("related"):
        merged["related"] = rec["related"]
    return merged


def fetch_cwe(cwe_id: str) -> dict | None:
    """Return CWE entry with control objective/name. DB → snapshot → cache."""
    norm = _normalize(cwe_id)
    if not norm:
        return None
    db_entry = _from_catalog_db(norm)
    if db_entry is not None:
        return db_entry
    if norm in _SNAPSHOT:
        entry = dict(_SNAPSHOT[norm])
        entry["id"] = norm
        return entry
    cached = _read_cache(norm)
    if cached is not None:
        return cached or None
    return None


def store_cwe(cwe_id: str, entry: dict) -> None:
    """Persist an LLM-derived CWE entry so future lookups hit disk."""
    norm = _normalize(cwe_id)
    if norm:
        _write_cache(norm, entry)


def extract_cwe_ids(text: str) -> list[str]:
    if not text:
        return []
    found = re.findall(r"CWE-\d{1,5}", text, flags=re.IGNORECASE)
    seen = []
    for c in found:
        upper = c.upper()
        if upper not in seen:
            seen.append(upper)
    return seen
