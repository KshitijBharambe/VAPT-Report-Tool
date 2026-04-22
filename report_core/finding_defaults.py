"""Shared finding defaults and generic-value catalogs."""

_PLACEHOLDER_TEXT = {"", "[placeholder]", "[insufficient data]", "nan", "none"}

_REC_TIER_LABELS = (
    ("primary", "Primary"),
    ("secondary", "Secondary"),
    ("defensive", "Defensive"),
)

_GENERIC_AUDIT_REQUIREMENT_FALLBACK = "Verify the affected service is securely configured, unnecessary exposure is removed, and periodic review and monitoring are in place."
_GENERIC_REFERENCE_FALLBACK = "OWASP Web Security Top 10, SANS25"
_GENERIC_CONTROL_OBJECTIVE_FALLBACK = (
    "Identify and remediate the vulnerability to reduce the attack surface."
)
_GENERIC_CONTROL_NAME_FALLBACK = "Vulnerability Remediation"

_STRUCTURED_GENERIC_LOOKUP_VALUES = {
    "control_objective": {
        _GENERIC_CONTROL_OBJECTIVE_FALLBACK,
        "Ensure that either the remote server is running the most updated version of the software, operating systems or application or has security guardrails such as network isolation or privileged access control to ensure the legacy/outdated system runs securely.",
        "Ensure that either the remote server is running the most updated version of the software, operating systems or application or has security guardrails such as network isolation or privileged access control to ensure the legacy/outdated system runs securely",
    },
    "control_name": {_GENERIC_CONTROL_NAME_FALLBACK},
    "audit_requirement": {
        _GENERIC_AUDIT_REQUIREMENT_FALLBACK,
        "Verify that the recommended control is implemented and periodically reviewed.",
    },
    "reference": {_GENERIC_REFERENCE_FALLBACK, "OWASP Top 10; SANS CWE Top 25"},
}

_GENERIC_REMEDIATION_PHRASES = (
    "update the software",
    "apply patches",
    "monitor the system",
    "keep software up to date",
    "install the latest",
)

_MIN_LEN = {
    "control_objective": 40,
    "control_name": 6,
    "audit_requirement": 30,
    "description": 30,
    "remediation": 40,
}

_CATEGORY_KEYWORDS = (
    (("ssl", "tls", "cipher", "certificate", "https"), "Cryptographic Configuration"),
    (
        ("snmp", "smb", "rdp", "telnet", "ftp", "netbios", "ntp", "dns"),
        "Network Service Configuration",
    ),
    (
        ("xss", "sql injection", "csrf", "directory traversal", "lfi", "rfi", "ssrf"),
        "Web Application",
    ),
    (
        (
            "patch",
            "outdated",
            "unsupported",
            "end-of-life",
            "version disclosure",
            "obsolete",
        ),
        "Software Patch Management",
    ),
    (
        ("default credential", "weak password", "anonymous", "guest"),
        "Authentication & Access Control",
    ),
)

_BUSINESS_IMPACT_TEMPLATES = {
    "Critical": (
        "Successful exploitation of {name} could allow an attacker to compromise the affected service, "
        "leading to unauthorised data access, service disruption, or lateral movement within the network. "
        "The resulting impact spans confidentiality, integrity, and availability and may carry regulatory, "
        "contractual, and reputational consequences for the organisation."
    ),
    "High": (
        "Exploitation of {name} could let an attacker bypass intended security controls or expose sensitive "
        "information, materially weakening the security posture of the affected service. "
        "Left unremediated the issue raises the likelihood of data exposure, service disruption, "
        "and downstream compliance findings."
    ),
    "Medium": (
        "{name} weakens defence-in-depth controls and provides an attacker with information or footholds "
        "that aid further exploitation. The direct impact is moderate but the issue meaningfully "
        "increases overall residual risk and audit exposure."
    ),
    "Low": (
        "{name} represents an incremental weakness in the affected service. Direct impact is limited, "
        "but the issue erodes hardening guarantees and may assist an attacker chaining other vulnerabilities."
    ),
    "Informational": (
        "{name} reflects a configuration weakness with no direct exploit path. The information disclosed "
        "or behaviour observed assists reconnaissance and may enable more targeted follow-on attacks."
    ),
}
