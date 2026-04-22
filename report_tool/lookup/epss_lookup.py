"""EPSS (Exploit Prediction Scoring System) lookup via FIRST.org API.

Public entry: fetch_epss(cve_id) -> dict | None
Returns {cve, epss, percentile, date} or None on miss.
EPSS score = probability of exploitation in next 30 days (0.0–1.0).
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import httpx

_EPSS_URL = "https://api.first.org/data/v1/epss"
_CACHE_DIR = Path.home() / ".cache" / "sqtk-tools" / "epss"
_CACHE_TTL_DAYS = 7
_MIN_INTERVAL_SEC = 1.0
_last_call_ts = 0.0


def _cache_path(cve_id: str) -> Path:
    return _CACHE_DIR / f"{cve_id}.json"


def _cache_valid(path: Path) -> bool:
    if not path.exists():
        return False
    age_days = (time.time() - path.stat().st_mtime) / 86400
    return age_days < _CACHE_TTL_DAYS


def _read_cache(cve_id: str) -> dict | None:
    path = _cache_path(cve_id)
    if not _cache_valid(path):
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


_MEM_CACHE: dict[str, dict | None] = {}


def fetch_epss(cve_id: str, timeout: float = 10.0) -> dict | None:
    """Fetch EPSS score for a CVE. Cached 7 days. Returns None on miss."""
    if not cve_id:
        return None
    norm = cve_id.strip().upper()
    if norm in _MEM_CACHE:
        return _MEM_CACHE[norm]
    cached = _read_cache(norm)
    if cached is not None:
        _MEM_CACHE[norm] = cached or None
        return cached or None
    _throttle()
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(_EPSS_URL, params={"cve": norm})
            if resp.status_code == 404:
                _write_cache(norm, {})
                _MEM_CACHE[norm] = None
                return None
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError):
        return None
    items = data.get("data") or []
    if not items:
        _write_cache(norm, {})
        _MEM_CACHE[norm] = None
        return None
    item = items[0]
    result = {
        "cve": item.get("cve", norm),
        "epss": float(item.get("epss", 0)),
        "percentile": float(item.get("percentile", 0)),
        "date": item.get("date", ""),
    }
    _write_cache(norm, result)
    _MEM_CACHE[norm] = result
    return result


def fetch_epss_batch(cve_ids: list[str], timeout: float = 15.0) -> dict[str, dict]:
    """Fetch EPSS for multiple CVEs in one call. Returns {cve_id: epss_dict}."""
    if not cve_ids:
        return {}
    norms = [c.strip().upper() for c in cve_ids if c]
    results: dict[str, dict] = {}
    missing: list[str] = []
    for cid in norms:
        if cid in _MEM_CACHE and _MEM_CACHE[cid]:
            results[cid] = _MEM_CACHE[cid]
        elif (cached := _read_cache(cid)) is not None:
            if cached:
                results[cid] = cached
                _MEM_CACHE[cid] = cached
        else:
            missing.append(cid)
    if not missing:
        return results
    _throttle()
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(_EPSS_URL, params={"cve": ",".join(missing)})
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError):
        return results
    for item in data.get("data") or []:
        cid = (item.get("cve") or "").upper()
        if not cid:
            continue
        entry = {
            "cve": cid,
            "epss": float(item.get("epss", 0)),
            "percentile": float(item.get("percentile", 0)),
            "date": item.get("date", ""),
        }
        results[cid] = entry
        _MEM_CACHE[cid] = entry
        _write_cache(cid, entry)
    return results


def epss_label(epss_score: float) -> str:
    """Human-readable exploitation likelihood label."""
    if epss_score >= 0.7:
        return "very high"
    if epss_score >= 0.4:
        return "high"
    if epss_score >= 0.1:
        return "medium"
    if epss_score >= 0.01:
        return "low"
    return "very low"
