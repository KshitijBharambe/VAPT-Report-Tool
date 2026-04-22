"""Static recommendation templates extracted from handmade reports.

These templates can be used WITHOUT LLM generation for common vulnerability categories.
Each template follows the 3-tier structure:
1. Primary Fix: The definitive remediation
2. Alternative/Compensating Control: When primary isn't feasible
3. Defensive/Detection: Monitoring, logging, isolation
"""

import re
from typing import Optional

from report_tool.recommendation_store import (
    get_eol_upgrade_paths,
    get_recommendation_templates,
    get_service_hardening,
)

# Compatibility aliases for existing callers/imports.
RECOMMENDATION_TEMPLATES = dict(get_recommendation_templates())
EOL_UPGRADE_PATHS = dict(get_eol_upgrade_paths())
SERVICE_HARDENING = dict(get_service_hardening())


# ═══════════════════════════════════════════════════════════════════════════════
# TEMPLATE SELECTION LOGIC
# ═══════════════════════════════════════════════════════════════════════════════


def select_recommendation_template(
    title: str, cve: Optional[str] = None, plugin_output: Optional[str] = None
) -> tuple[Optional[str], dict]:
    """Select the appropriate recommendation template based on vulnerability title.

    Returns:
        tuple of (template_key, variables_dict) or (None, {}) if no template matches.
    """
    title_lower = title.lower()

    # ─── SSH Issues (check BEFORE generic cipher patterns) ────────────────────
    if "ssh" in title_lower and any(
        x in title_lower for x in ["cbc", "weak cipher", "cipher", "weak algorithm"]
    ):
        return "ssh_weak_ciphers", {}

    # ─── SSL/TLS Cipher Issues ────────────────────────────────────────────────
    if any(
        x in title_lower
        for x in ["cipher", "sweet32", "medium strength", "weak cipher"]
    ):
        cipher_type = (
            "medium strength ciphers (3DES)"
            if "medium" in title_lower
            else "weak cipher suites"
        )
        if "anonymous" in title_lower:
            cipher_type = "anonymous cipher suites"
        return "cipher_weakness", {"weak_cipher_types": cipher_type}

    # ─── Deprecated TLS ───────────────────────────────────────────────────────
    if any(
        x in title_lower
        for x in [
            "tls 1.0",
            "tls 1.1",
            "sslv2",
            "sslv3",
            "ssl v2",
            "ssl v3",
            "ssl version 2",
            "ssl version 3",
            "deprecated protocol",
            "deprecated tls",
        ]
    ):
        if "1.0" in title_lower and "1.1" in title_lower:
            ver = "TLS 1.0 and 1.1"
        elif "1.0" in title_lower:
            ver = "TLS 1.0"
        elif "1.1" in title_lower:
            ver = "TLS 1.1"
        elif "version 2" in title_lower and "version 3" in title_lower:
            ver = "SSLv2 and SSLv3"
        elif (
            "sslv2" in title_lower
            or "ssl v2" in title_lower
            or "version 2" in title_lower
        ):
            ver = "SSLv2"
        elif (
            "sslv3" in title_lower
            or "ssl v3" in title_lower
            or "version 3" in title_lower
        ):
            ver = "SSLv3"
        else:
            ver = "deprecated TLS versions"
        return "deprecated_tls", {"deprecated_version": ver}

    # ─── Injection Vulnerabilities ────────────────────────────────────────────
    if any(x in title_lower for x in ["sql injection", "sqli", "sql inj"]):
        return "sql_injection", {}
    if any(
        x in title_lower
        for x in ["cross-site scripting", "xss", "cross site scripting"]
    ):
        return "xss", {}
    if any(
        x in title_lower for x in ["command injection", "cmd injection", "os command"]
    ):
        return "command_injection", {}

    # ─── Certificate Issues ───────────────────────────────────────────────────
    if "self-signed" in title_lower or "self signed" in title_lower:
        return "self_signed_cert", {}
    if any(
        x in title_lower
        for x in ["certificate expir", "cert expir", "expired certificate"]
    ):
        return "certificate_expiry", {}
    if any(x in title_lower for x in ["hostname", "wrong hostname", "cn mismatch"]):
        return "certificate_hostname", {}
    if any(
        x in title_lower
        for x in ["cannot be trusted", "untrusted certificate", "invalid certificate"]
    ):
        return "certificate_trust", {}
    if any(
        x in title_lower
        for x in ["weak hash", "sha-1 certificate", "md5 certificate", "sha1 sign"]
    ):
        return "certificate_weak_hash", {}

    # ─── EOL Operating Systems ────────────────────────────────────────────────
    for os_key, data in EOL_UPGRADE_PATHS.items():
        if os_key in title_lower:
            return data["template"], {"upgrade_targets": data["upgrade_targets"]}
    if any(
        x in title_lower
        for x in ["unsupported version", "end of life", "eol", "end-of-life"]
    ):
        return "eol_generic", {}

    # ─── SNMP ─────────────────────────────────────────────────────────────────
    if "snmp" in title_lower and any(
        x in title_lower for x in ["default", "community", "public"]
    ):
        return "snmp_default", {}

    # ─── SMB Signing ──────────────────────────────────────────────────────────
    if "smb" in title_lower and "signing" in title_lower:
        return "smb_signing", {}

    # ─── Security Headers ─────────────────────────────────────────────────────
    if (
        "hsts" in title_lower
        or "strict-transport-security" in title_lower
        or "strict transport security" in title_lower
    ):
        return "hsts_missing", {}
    if (
        "clickjacking" in title_lower
        or "x-frame-options" in title_lower
        or "frame-ancestors" in title_lower
    ):
        return "clickjacking", {}
    if "security header" in title_lower:
        return "security_headers_generic", {}

    # ─── Legacy Network Services ──────────────────────────────────────────────
    legacy_services = {
        "echo service": "Echo Service",
        "quote of the day": "Quote of the Day Service",
        "qotd": "Quote of the Day Service",
        "daytime service": "Daytime Service",
        "chargen": "Chargen Service",
        "discard service": "Discard Service",
    }
    for pattern, service_name in legacy_services.items():
        if pattern in title_lower:
            return "legacy_service", {"service_name": service_name}

    # ─── Database/Service Exposure ────────────────────────────────────────────
    exposed_services = [
        "elasticsearch",
        "mongodb",
        "redis",
        "memcached",
        "couchdb",
        "cassandra",
    ]
    for svc in exposed_services:
        if svc in title_lower and any(
            x in title_lower
            for x in [
                "exposed",
                "unauthorized",
                "information disclosure",
                "open access",
            ]
        ):
            return "database_exposure", {"service": svc.title()}

    # ─── RCE Vulnerabilities (Generic) ────────────────────────────────────────
    if any(
        x in title_lower for x in [" rce", "remote code execution", "code execution"]
    ):
        # Extract product name
        product = (
            title.split("RCE")[0].strip()
            if "RCE" in title
            else title.split("Remote Code")[0].strip()
        )
        return "rce_generic", {"product": product}

    # ─── Service Exposed (Generic) ────────────────────────────────────────────
    if (
        any(x in title_lower for x in ["exposed", "service exposed"])
        and "certificate" not in title_lower
    ):
        # Extract service name
        service = (
            title.replace("Exposed", "")
            .replace("Service", "")
            .replace("Server", "")
            .strip()
        )
        return "service_exposure", {"service": service}

    # ─── Autocomplete (broader match) ─────────────────────────────────────────
    if "autocomplete" in title_lower or (
        "password" in title_lower and "auto" in title_lower
    ):
        return "autocomplete_enabled", {}

    # ─── RDP ──────────────────────────────────────────────────────────────────
    if any(x in title_lower for x in ["rdp", "remote desktop"]) and any(
        x in title_lower for x in ["exposed", "nla", "encryption"]
    ):
        return "rdp_exposure", {}

    # ─── DNS Dynamic Update ───────────────────────────────────────────────────
    if "dns" in title_lower and any(
        x in title_lower for x in ["dynamic update", "record injection"]
    ):
        return "dns_dynamic_update", {}

    # ─── ICMP Timestamp ───────────────────────────────────────────────────────
    if "icmp" in title_lower and "timestamp" in title_lower:
        return "icmp_timestamp", {}

    # ─── Directory Listing ────────────────────────────────────────────────────
    if any(
        x in title_lower
        for x in [
            "directory listing",
            "directory browsing",
            "browsable",
            "directory enumeration",
        ]
    ):
        return "directory_listing", {}

    # ─── Autocomplete ─────────────────────────────────────────────────────────
    if "autocomplete" in title_lower and any(
        x in title_lower for x in ["password", "enabled"]
    ):
        return "autocomplete_enabled", {}

    # ─── Service-Specific Outdated Versions ───────────────────────────────────
    for service, template_key in SERVICE_HARDENING.items():
        if service in title_lower:
            # Extract version if present
            version_match = re.search(r"<\s*(\d+\.\d+(?:\.\d+)?)", title)
            fixed_version = version_match.group(1) if version_match else "latest"
            return template_key, {"fixed_version": fixed_version}

    # ─── Generic Outdated Service (with version number) ──────────────────────
    version_match = re.search(r"<\s*(\d+\.\d+(?:\.\d+)?)", title)
    if version_match:
        # Extract product name (everything before "<")
        product = title.split("<")[0].strip()
        return "outdated_service_generic", {
            "product": product,
            "fixed_version": version_match.group(1),
        }

    # ─── No Match ─────────────────────────────────────────────────────────────
    return None, {}


def get_recommendation(
    title: str,
    cve: Optional[str] = None,
    plugin_output: Optional[str] = None,
) -> Optional[str]:
    """Get a formatted recommendation for the given vulnerability.

    Returns:
        Formatted recommendation string, or None if no template matches.
    """
    template_key, variables = select_recommendation_template(title, cve, plugin_output)
    if template_key is None:
        return None

    template = RECOMMENDATION_TEMPLATES.get(template_key)
    if template is None:
        return None

    try:
        return template.format(**variables)
    except KeyError:
        # Missing variables - return template as-is
        return template


def has_template_match(title: str) -> bool:
    """Check if a static template exists for the given vulnerability title."""
    template_key, _ = select_recommendation_template(title)
    return template_key is not None
