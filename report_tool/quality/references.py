"""Reference URL validation + normalization.

Post-generation pass over a report: HEAD/GET each reference URL, drop 404 /
login-redirect / dead domains. Optionally auto-adds canonical NVD + MITRE CWE
URLs from the finding's CVE/CWE ids when missing.
"""

from __future__ import annotations

import re
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Mapping

from report_core.privacy import (
    ClientDataInternetEgressError,
    assert_reference_url_safe_for_egress,
)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-\d{1,5}", re.IGNORECASE)

_NVD_URL = "https://nvd.nist.gov/vuln/detail/{cve}"
_CWE_URL = "https://cwe.mitre.org/data/definitions/{num}.html"

_LOGIN_MARKERS = ("sign in", "log in", "login", "authentication required")
_URL_RE = re.compile(r"https?://[^\s<>\]\)\"']+", re.IGNORECASE)

# Priority order: NVD > MITRE > vendor advisories > OWASP > generic.
# Lower value = higher priority (sorted ascending).
_DOMAIN_PRIORITY: tuple[tuple[str, int], ...] = (
    ("nvd.nist.gov", 0),
    ("cve.mitre.org", 1),
    ("cwe.mitre.org", 1),
    ("capec.mitre.org", 1),
    ("attack.mitre.org", 1),
    ("msrc.microsoft.com", 2),
    ("support.microsoft.com", 2),
    ("access.redhat.com", 2),
    ("ubuntu.com", 2),
    ("debian.org", 2),
    ("cisco.com", 2),
    ("oracle.com", 2),
    ("vmware.com", 2),
    ("apple.com", 2),
    ("github.com/advisories", 2),
    ("owasp.org", 3),
    ("cheatsheetseries.owasp.org", 3),
    ("sans.org", 3),
    ("nist.gov", 3),
)


def _ref_priority(url: str) -> int:
    host = urllib.parse.urlparse(_normalize_url(url)).netloc.lower()
    if not host:
        return 9
    path = urllib.parse.urlparse(_normalize_url(url)).path.lower()
    full = host + path
    for marker, rank in _DOMAIN_PRIORITY:
        if marker in full:
            return rank
    return 5  # generic

_VALIDATION_CACHE: dict[str, tuple[bool, int]] = {}
_CACHE_LOCK = threading.Lock()


def _normalize_url(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return ""
    if not urllib.parse.urlparse(u).scheme:
        u = "https://" + u
    return u


def _canonical_key(url: str) -> str:
    """Dedup key: scheme+host+path, query/fragment dropped."""
    p = urllib.parse.urlparse(_normalize_url(url))
    return f"{p.scheme}://{p.netloc.lower()}{p.path.rstrip('/')}"


def _check_url(url: str, timeout: float = 8.0) -> tuple[bool, int]:
    """Return (is_live, status_code). Cached."""
    assert_reference_url_safe_for_egress(url)
    try:
        import httpx
    except ImportError:
        return True, 0  # no http lib: assume live, skip validation

    key = _canonical_key(url)
    with _CACHE_LOCK:
        cached = _VALIDATION_CACHE.get(key)
        if cached is not None:
            return cached

    ok = False
    status = 0
    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "Sqtk-Tools/ref-check"},
        ) as client:
            try:
                resp = client.head(url)
                status = resp.status_code
                if status in (401, 403, 405):
                    resp = client.get(url)
                    status = resp.status_code
            except httpx.HTTPError:
                resp = client.get(url)
                status = resp.status_code
        if 200 <= status < 400:
            body = (getattr(resp, "text", "") or "").lower()[:4000]
            if any(m in body for m in _LOGIN_MARKERS) and "password" in body:
                ok = False
            else:
                ok = True
    except Exception:
        ok = False

    with _CACHE_LOCK:
        _VALIDATION_CACHE[key] = (ok, status)
    return ok, status


def _extract_refs(value: Any) -> list[dict]:
    """Normalize the many shapes a 'reference' field can take into list[dict]."""
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        urls = list(dict.fromkeys(_URL_RE.findall(text)))
        refs = [{"title": url, "url": url} for url in urls]
        remainder = text
        for url in urls:
            remainder = remainder.replace(url, "\n")
        for part in [p.strip(" -\t\r") for p in remainder.splitlines() if p.strip()]:
            lowered = part.casefold()
            if lowered in {"owasp web security top 10", "sans25", "owasp top 10"}:
                continue
            if len(part) < 8:
                continue
            refs.append({"title": part, "url": ""})
        return refs
    if isinstance(value, dict):
        return [{"title": value.get("title", ""), "url": value.get("url", "")}]
    if isinstance(value, (list, tuple)):
        out: list[dict] = []
        for item in value:
            if isinstance(item, str):
                out.append(
                    {"title": item, "url": item if item.startswith("http") else ""}
                )
            elif isinstance(item, dict):
                out.append(
                    {
                        "title": item.get("title") or item.get("name") or "",
                        "url": item.get("url") or item.get("href") or "",
                    }
                )
        return out
    return []


def _dedup(refs: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for r in refs:
        key = _canonical_key(r.get("url") or r.get("title") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def _auto_refs(finding: Mapping[str, Any]) -> list[dict]:
    """Canonical refs derived from CVE/CWE ids (always live)."""
    blob = " ".join(
        str(finding.get(f) or "")
        for f in ("cve", "description", "proof_of_concept", "remediation")
    )
    cves = list(dict.fromkeys(_CVE_RE.findall(blob) + _CVE_RE.findall(str(finding.get("cve") or ""))))
    cwes = list(dict.fromkeys(_CWE_RE.findall(blob) + _CWE_RE.findall(str(finding.get("cwe") or ""))))
    out: list[dict] = []
    for c in cves[:3]:
        out.append(
            {
                "title": f"NVD {c.upper()}",
                "url": _NVD_URL.format(cve=c.upper()),
            }
        )
    for c in cwes[:2]:
        num = c.upper().replace("CWE-", "")
        out.append({"title": c.upper(), "url": _CWE_URL.format(num=num)})
    return out


def validate_finding_refs(
    finding: dict,
    *,
    add_canonical: bool = True,
    max_workers: int = 8,
    timeout: float = 8.0,
) -> dict:
    """Mutate + return the finding with validated `reference` list.

    Behavior:
      - Merge existing refs with canonical auto-refs (when `add_canonical`).
      - Drop URLs that HEAD/GET as 4xx/5xx or look like login-walls.
      - Preserve string-only entries (titles) with empty URL.
      - Return the finding with `reference` replaced.
    """
    existing = _extract_refs(finding.get("reference"))
    if add_canonical:
        existing = existing + _auto_refs(finding)
    existing = _dedup(existing)

    url_refs = [r for r in existing if r.get("url")]
    noop_refs = [r for r in existing if not r.get("url")]
    safe_url_refs: list[dict] = []
    skipped_url_refs: list[dict] = []
    for ref in url_refs:
        try:
            assert_reference_url_safe_for_egress(ref["url"])
        except ClientDataInternetEgressError:
            skipped_url_refs.append(ref)
        else:
            safe_url_refs.append(ref)

    live: list[dict] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_check_url, r["url"], timeout): r for r in safe_url_refs}
        for fut in as_completed(futs):
            r = futs[fut]
            try:
                ok, status = fut.result()
            except Exception:
                ok, status = False, 0
            if ok:
                r = dict(r)
                r["status"] = status
                live.append(r)

    live.sort(key=lambda r: (_ref_priority(r.get("url", "")), r.get("title", "")))
    max_refs = 10
    finding["reference"] = (noop_refs + skipped_url_refs + live)[:max_refs]
    return finding


def validate_report_refs(
    report: Mapping[str, Any],
    *,
    add_canonical: bool = True,
    max_workers: int = 8,
    timeout: float = 8.0,
) -> dict:
    """Run validate_finding_refs across all findings in a report. Mutates."""
    findings = report.get("findings") or []
    for f in findings:
        if isinstance(f, dict):
            validate_finding_refs(
                f,
                add_canonical=add_canonical,
                max_workers=max_workers,
                timeout=timeout,
            )
    return dict(report)


def main() -> None:
    import argparse
    import json
    import sys

    ap = argparse.ArgumentParser(description="Validate reference URLs in a report")
    ap.add_argument("report", help="Path to report JSON")
    ap.add_argument(
        "--no-canonical",
        action="store_true",
        help="Do not add NVD/CWE canonical URLs",
    )
    ap.add_argument("--out", default=None, help="Write validated JSON here")
    args = ap.parse_args()

    with open(args.report, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    validate_report_refs(data, add_canonical=not args.no_canonical)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        print(f"Wrote {args.out}")
    else:
        json.dump(data, sys.stdout, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
