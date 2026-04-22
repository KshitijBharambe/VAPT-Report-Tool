"""Privacy guard — sanitize sensitive data before internet egress."""

import ipaddress
import re
import urllib.parse
from typing import Any, Tuple

# Fields that may contain sensitive infrastructure details
_SENSITIVE_FIELDS = (
    "description",
    "business_impact",
    "proof_of_concept",
    "remediation",
    "affected_assets",
    "audit_requirement",
)

# Regex patterns for sensitive data
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
_FQDN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_URL_PATTERN = re.compile(r"\bhttps?://[^\s<>'\"`]+", re.IGNORECASE)
_WINDOWS_USER_PATTERN = re.compile(r"\b[A-Za-z0-9._-]+\\[A-Za-z0-9._-]+\b")
_PLACEHOLDER_PATTERN = re.compile(r"\[[A-Z]+_\d+\]")
_LABELED_SECRET_PATTERN = re.compile(
    r"(?im)^(?P<label>"
    r"client|customer|company|organization|organisation|org|project|engagement|"
    r"tenant|subscription|account|environment|scope|owner|contact|hostname|host|"
    r"server|asset|target|computer name|fqdn|domain|url|uri|username|user|login|"
    r"email|ticket|case|change|request|jira|servicenow"
    r")\s*[:=]\s*(?P<value>.+)$"
)
_SCHEMA_SUFFIXES = frozenset(
    {
        "primary",
        "secondary",
        "defensive",
        "title",
        "url",
        "name",
        "id",
        "description",
        "status",
        "objective",
        "requirement",
        "impact",
        "assets",
        "context",
        "provider",
        "model",
        "schema",
        "json",
        "value",
        "field",
    }
)
# Common non-sensitive FQDNs to skip (public references)
_PUBLIC_DOMAINS = frozenset(
    {
        "owasp.org",
        "nist.gov",
        "cve.org",
        "mitre.org",
        "cwe.mitre.org",
        "nvd.nist.gov",
        "sans.org",
        "exploit-db.com",
        "github.com",
        "microsoft.com",
        "apache.org",
        "openssl.org",
        "mozilla.org",
        "letsencrypt.org",
        "digicert.com",
        "ubuntu.com",
        "debian.org",
        "redhat.com",
        "jenkins.io",
        "elastic.co",
        "python.org",
        "attack.mitre.org",
        "capec.mitre.org",
        "msrc.microsoft.com",
        "support.microsoft.com",
        "access.redhat.com",
        "oracle.com",
        "vmware.com",
        "apple.com",
        "cisco.com",
        "raw.githubusercontent.com",
        "testssl.sh",
    }
)


def is_cloud_provider(config: dict) -> bool:
    """Return True if the configured LLM provider routes over the internet."""
    provider = config.get("llm", {}).get("provider", "local")
    return provider != "local"


def _assign_placeholder(restore_map: dict, prefix: str, original: str) -> str:
    original = str(original or "")
    if _PLACEHOLDER_PATTERN.fullmatch(original):
        return original
    for placeholder, value in restore_map.items():
        if value == original:
            return placeholder
    counter = sum(1 for key in restore_map if key.startswith(f"[{prefix}_"))
    placeholder = f"[{prefix}_{counter + 1}]"
    restore_map[placeholder] = original
    return placeholder


def _placeholder_prefix(label: str) -> str:
    label = (label or "").strip().lower()
    if label in {"client", "customer", "company", "organization", "organisation", "org"}:
        return "CLIENT"
    if label in {"project", "engagement", "tenant", "subscription", "account"}:
        return "PROJECT"
    if label in {"hostname", "host", "server", "asset", "target", "computer name", "fqdn", "domain"}:
        return "ASSET"
    if label in {"url", "uri"}:
        return "URL"
    if label in {"username", "user", "login", "owner", "contact", "email"}:
        return "USER"
    if label in {"ticket", "case", "change", "request", "jira", "servicenow"}:
        return "TICKET"
    return "CONTEXT"


def _host_is_public_reference_host(host: str) -> bool:
    host = (host or "").strip().lower()
    if not host:
        return False
    return any(host == domain or host.endswith("." + domain) for domain in _PUBLIC_DOMAINS)


def _looks_like_schema_token(host: str) -> bool:
    parts = [part for part in str(host or "").strip().lower().split(".") if part]
    if len(parts) < 2:
        return False
    if not all(re.fullmatch(r"[a-z_]+", part) for part in parts):
        return False
    return parts[-1] in _SCHEMA_SUFFIXES


def _url_is_public_reference(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return False
    if (parsed.scheme or "").lower() not in {"http", "https"}:
        return False
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return _host_is_public_reference_host(host)
    return False


def _build_ip_map(text: str, existing_map: dict) -> dict:
    """Find all IPs in text and assign placeholders."""
    ip_map = dict(existing_map)
    for match in _IP_PATTERN.finditer(text):
        ip = match.group()
        if ip not in ip_map.values():
            _assign_placeholder(ip_map, "IP", ip)
    return ip_map


def _build_url_map(text: str, existing_map: dict) -> dict:
    url_map = dict(existing_map)
    for match in _URL_PATTERN.finditer(text):
        url = match.group().rstrip(").,;")
        if _url_is_public_reference(url):
            continue
        _assign_placeholder(url_map, "URL", url)
    return url_map


def _build_host_map(text: str, existing_map: dict) -> dict:
    """Find all FQDNs in text and assign placeholders, skipping public domains."""
    host_map = dict(existing_map)
    for match in _FQDN_PATTERN.finditer(text):
        fqdn = match.group().lower()
        # Skip public/well-known domains
        if _looks_like_schema_token(fqdn):
            continue
        if any(fqdn.endswith(d) or fqdn == d for d in _PUBLIC_DOMAINS):
            continue
        if fqdn not in [v.lower() for v in host_map.values()]:
            _assign_placeholder(host_map, "HOST", match.group())
    return host_map


def _build_email_map(text: str, existing_map: dict) -> dict:
    email_map = dict(existing_map)
    for match in _EMAIL_PATTERN.finditer(text):
        _assign_placeholder(email_map, "EMAIL", match.group())
    return email_map


def _build_windows_user_map(text: str, existing_map: dict) -> dict:
    user_map = dict(existing_map)
    for match in _WINDOWS_USER_PATTERN.finditer(text):
        _assign_placeholder(user_map, "USER", match.group())
    return user_map


def _build_labeled_secret_map(text: str, existing_map: dict) -> dict:
    secret_map = dict(existing_map)
    for match in _LABELED_SECRET_PATTERN.finditer(text):
        value = str(match.group("value") or "").strip()
        if not value:
            continue
        _assign_placeholder(secret_map, _placeholder_prefix(match.group("label")), value)
    return secret_map


def _apply_map(text: str, replace_map: dict) -> str:
    """Replace all original values in text with their placeholders."""
    if not text or not isinstance(text, str):
        return text
    result = text
    # Sort by length descending so longer matches replace first
    for placeholder, original in sorted(replace_map.items(), key=lambda x: -len(x[1])):
        result = result.replace(original, placeholder)
    return result


def _reverse_map(text: str, replace_map: dict) -> str:
    """Replace all placeholders in text with original values."""
    if not text or not isinstance(text, str):
        return text
    result = text
    for placeholder, original in replace_map.items():
        result = result.replace(placeholder, original)
    return result


def sanitize_text_for_egress(text: str, restore_map: dict | None = None) -> Tuple[str, dict]:
    """Replace client-identifying content with semantic placeholders."""
    if not text or not isinstance(text, str):
        return text, dict(restore_map or {})
    current_map = dict(restore_map or {})
    current_map = _build_labeled_secret_map(text, current_map)
    current_map = _build_url_map(text, current_map)
    current_map = _build_email_map(text, current_map)
    current_map = _build_windows_user_map(text, current_map)
    current_map = _build_ip_map(text, current_map)
    current_map = _build_host_map(text, current_map)
    return _apply_map(text, current_map), current_map


def sanitize_value_for_egress(
    value: Any,
    restore_map: dict | None = None,
) -> Tuple[Any, dict]:
    """Recursively sanitize strings nested inside dicts/lists/tuples."""
    current_map = dict(restore_map or {})
    if isinstance(value, str):
        sanitized, current_map = sanitize_text_for_egress(value, current_map)
        return sanitized, current_map
    if isinstance(value, list):
        items = []
        for item in value:
            sanitized_item, current_map = sanitize_value_for_egress(item, current_map)
            items.append(sanitized_item)
        return items, current_map
    if isinstance(value, tuple):
        items = []
        for item in value:
            sanitized_item, current_map = sanitize_value_for_egress(item, current_map)
            items.append(sanitized_item)
        return tuple(items), current_map
    if isinstance(value, dict):
        sanitized_dict = {}
        for key, item in value.items():
            sanitized_item, current_map = sanitize_value_for_egress(item, current_map)
            sanitized_dict[key] = sanitized_item
        return sanitized_dict, current_map
    return value, current_map


def restore_placeholders(value: Any, restore_map: dict) -> Any:
    """Recursively restore placeholders in strings, dicts, and lists."""
    if not restore_map:
        return value
    if isinstance(value, str):
        return _reverse_map(value, restore_map)
    if isinstance(value, list):
        return [restore_placeholders(item, restore_map) for item in value]
    if isinstance(value, tuple):
        return tuple(restore_placeholders(item, restore_map) for item in value)
    if isinstance(value, dict):
        return {
            key: restore_placeholders(item, restore_map) for key, item in value.items()
        }
    return value


def sanitize_finding(finding: dict) -> Tuple[dict, dict]:
    """
    Sanitize a finding dict by replacing sensitive strings with placeholders.

    Returns:
        (sanitized_finding, restore_map) where restore_map maps placeholder → original.
    """
    sanitized, restore_map = sanitize_value_for_egress(dict(finding), {})
    return dict(sanitized) if isinstance(sanitized, dict) else dict(finding), restore_map


def restore_finding(finding: dict, restore_map: dict) -> dict:
    """Restore all placeholders in a finding dict back to original values."""
    restored = restore_placeholders(finding, restore_map)
    return dict(restored) if isinstance(restored, dict) else finding


def sanitize_client_context(context: str) -> Tuple[str, dict]:
    """Sanitize client context string, stripping IPs and hostnames."""
    return sanitize_text_for_egress(context, {})


class EgressViolation(RuntimeError):
    """Raised when sensitive data is detected in an outbound cloud payload."""


class ClientDataInternetEgressError(RuntimeError):
    """Raised when client-derived data would leave the machine."""


_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def _iter_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _iter_strings(v)


def assert_safe_for_egress(payload) -> None:
    """Scan payload for IPs, private FQDNs, or emails. Raise EgressViolation on hit.

    Use immediately before any cloud LLM call. Fail-closed policy.
    """
    for text in _iter_strings(payload):
        if not text:
            continue
        ip_match = _IP_PATTERN.search(text)
        if ip_match:
            raise EgressViolation(f"IP address leaking to cloud: {ip_match.group()!r}")
        for match in _FQDN_PATTERN.finditer(text):
            host = match.group().lower()
            if _looks_like_schema_token(host):
                continue
            if any(host.endswith(d) or host == d for d in _PUBLIC_DOMAINS):
                continue
            raise EgressViolation(
                f"Private hostname leaking to cloud: {match.group()!r}"
            )
        email_match = _EMAIL_PATTERN.search(text)
        if email_match:
            raise EgressViolation(f"Email leaking to cloud: {email_match.group()!r}")


def _llm_destination(config: dict) -> str:
    llm_cfg = (config or {}).get("llm", {}) if isinstance(config, dict) else {}
    provider = str(llm_cfg.get("provider") or "remote provider").strip().lower()
    base_url = str(llm_cfg.get("base_url") or "").strip()
    if "openrouter.ai" in base_url or provider == "openrouter":
        return "OpenRouter"
    if base_url:
        try:
            host = urllib.parse.urlparse(base_url).hostname or ""
        except ValueError:
            host = ""
        if host:
            return host
    return provider or "remote provider"


def raise_client_data_egress_error(
    action: str,
    destination: str,
    detail: str = "",
) -> None:
    message = (
        f"Blocked internet egress: {action} would send client data to {destination}. "
        "No client data may leave this machine. Replace sensitive values with placeholders or use a local-only workflow and retry."
    )
    if detail:
        message += f" {detail}"
    raise ClientDataInternetEgressError(message)


def prepare_text_for_cloud_egress(
    text: str,
    config: dict,
    action: str,
) -> Tuple[str, dict]:
    """Sanitize cloud-bound text and fail only if sensitive material survives."""
    if not is_cloud_provider(config):
        return text, {}
    sanitized, restore_map = sanitize_text_for_egress(text)
    try:
        assert_safe_for_egress(sanitized)
    except EgressViolation as exc:
        raise_client_data_egress_error(
            action,
            _llm_destination(config),
            f"Sanitization could not safely remove all client data ({exc}).",
        )
    return sanitized, restore_map


def prepare_client_context_for_cloud(
    context: str,
    config: dict,
) -> Tuple[str, dict]:
    """Sanitize user-supplied client context for cloud use when possible."""
    if not is_cloud_provider(config):
        return str(context or ""), {}
    raw = str(context or "")
    if not raw.strip():
        return raw, {}
    sanitized, restore_map = sanitize_text_for_egress(raw)
    try:
        assert_safe_for_egress(sanitized)
    except EgressViolation as exc:
        raise_client_data_egress_error(
            "client context",
            _llm_destination(config),
            f"Sanitization could not safely remove all client data ({exc}).",
        )
    return sanitized, restore_map


def assert_clean_client_context_for_cloud(context: str, config: dict) -> None:
    """Legacy compatibility wrapper for client-context cloud preflight."""
    prepare_client_context_for_cloud(context, config)


def assert_reference_url_safe_for_egress(url: str) -> None:
    """Allow outbound reference validation only for vetted public HTTP(S) hosts."""
    normalized = (url or "").strip()
    if not normalized:
        return
    parsed = urllib.parse.urlparse(normalized)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        raise_client_data_egress_error(
            "reference validation",
            "a non-HTTP(S) destination",
            f"Refused outbound URL {normalized!r}.",
        )
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise_client_data_egress_error(
            "reference validation",
            "an unknown destination",
            f"Refused outbound URL {normalized!r}.",
        )
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        raise_client_data_egress_error(
            "reference validation",
            host,
            "Raw IP destinations are never fetched during outbound validation.",
        )
    if host.endswith(".local") or "." not in host:
        raise_client_data_egress_error(
            "reference validation",
            host,
            "Local-only hostnames are never fetched.",
        )
    if not _host_is_public_reference_host(host):
        raise_client_data_egress_error(
            "reference validation",
            host,
            "Only vetted public security-reference domains are allowed for outbound checks.",
        )
