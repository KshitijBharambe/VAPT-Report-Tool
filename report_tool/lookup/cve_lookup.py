"""NVD CVE API lookup with disk cache and polite rate limiting.

Public entry: fetch_cve(cve_id) -> dict | None
Returns {id, description, cvss_v31, severity, cwes, references} or None on miss.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import httpx

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CACHE_DIR = Path.home() / ".cache" / "sqtk-tools" / "cve"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_MIN_INTERVAL_SEC = 6.5  # NVD anon: 5 req/30s → 6s min spacing
_last_call_ts = 0.0


def _normalize(cve_id: str) -> str | None:
    if not cve_id:
        return None
    cid = cve_id.strip().upper()
    return cid if _CVE_RE.match(cid) else None


def _cache_path(cve_id: str) -> Path:
    return _CACHE_DIR / f"{cve_id}.json"


def _read_cache(cve_id: str) -> dict | None:
    path = _cache_path(cve_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _write_cache(cve_id: str, data: dict) -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _cache_path(cve_id).write_text(json.dumps(data, indent=2))
    except OSError:
        pass


def _throttle() -> None:
    global _last_call_ts
    elapsed = time.monotonic() - _last_call_ts
    if elapsed < _MIN_INTERVAL_SEC:
        time.sleep(_MIN_INTERVAL_SEC - elapsed)
    _last_call_ts = time.monotonic()


def _parse_nvd(raw: dict) -> dict | None:
    vulns = raw.get("vulnerabilities") or []
    if not vulns:
        return None
    cve = vulns[0].get("cve", {})
    descriptions = cve.get("descriptions", [])
    desc_en = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"), ""
    )
    metrics = cve.get("metrics", {})
    cvss = None
    severity = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            cvss = data.get("baseScore")
            severity = (
                data.get("baseSeverity")
                or entries[0].get("baseSeverity")
            )
            break
    cwes = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-") and val not in cwes:
                cwes.append(val)
    refs = [
        {"url": r.get("url", ""), "tags": r.get("tags", [])}
        for r in cve.get("references", [])
        if r.get("url")
    ]
    return {
        "id": cve.get("id", ""),
        "description": desc_en,
        "cvss": cvss,
        "severity": severity,
        "cwes": cwes,
        "references": refs[:8],
    }


_MEM_CACHE: dict[str, dict | None] = {}


def fetch_cve(cve_id: str, timeout: float = 15.0) -> dict | None:
    """Fetch CVE metadata from NVD. Cached on disk. Returns None on miss/error."""
    norm = _normalize(cve_id)
    if not norm:
        return None
    if norm in _MEM_CACHE:
        return _MEM_CACHE[norm]
    cached = _read_cache(norm)
    if cached is not None:
        _MEM_CACHE[norm] = cached or None
        return cached or None
    _throttle()
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(_NVD_URL, params={"cveId": norm})
            if resp.status_code == 404:
                _write_cache(norm, {})
                return None
            resp.raise_for_status()
            parsed = _parse_nvd(resp.json())
    except (httpx.HTTPError, ValueError):
        return None
    if parsed:
        _write_cache(norm, parsed)
    _MEM_CACHE[norm] = parsed
    return parsed


def extract_cve_ids(text: str) -> list[str]:
    """Extract all CVE IDs from a string."""
    if not text:
        return []
    found = re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)
    seen = []
    for c in found:
        upper = c.upper()
        if upper not in seen:
            seen.append(upper)
    return seen
