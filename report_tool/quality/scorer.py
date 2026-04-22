"""VAPT finding quality scorer.

Heuristics-only. No LLM. Cheap. Run over generated report JSON to flag
low-quality findings before they ship. Optional TF-IDF cosine vs a handmade
baseline corpus when available.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

_GENERIC_PHRASES = (
    "update the software",
    "apply patches",
    "monitor the system",
    "keep software up to date",
    "install the latest",
    "ensure that either the remote server",
    "apply security best practices",
)

_MIN_LEN = {
    "control_objective": 60,
    "control_name": 6,
    "audit_requirement": 40,
    "description": 40,
    "remediation": 60,
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)
_VERSION_RE = re.compile(r"\b\d+(?:\.\d+){1,3}\b")
_PORT_RE = re.compile(r"\b(?:TCP|UDP)?/?\s*:?(\d{2,5})\b")


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return " ".join(str(v) for v in value if v)
    if isinstance(value, dict):
        return " ".join(str(v) for v in value.values() if v)
    return str(value)


def _has_generic_phrase(text: str) -> bool:
    low = text.lower()
    return any(p in low for p in _GENERIC_PHRASES)


def _length_score(field: str, text: str) -> float:
    min_len = _MIN_LEN.get(field, 0)
    if not text:
        return 0.0
    if len(text) >= min_len:
        return 1.0
    return len(text) / max(min_len, 1)


def _remediation_tier_score(value: Any) -> float:
    """Score 0-1: how close to the handmade 3-tier (primary/secondary/defensive)."""
    if isinstance(value, dict):
        tiers = sum(
            1
            for k in ("primary", "secondary", "defensive")
            if str(value.get(k, "") or "").strip()
        )
        return tiers / 3.0
    text = _text(value).strip()
    if not text:
        return 0.0
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return min(len(lines), 3) / 3.0


def _specificity_bonus(finding: Mapping[str, Any]) -> float:
    """Bonus for concrete markers: CVE IDs, versions, ports, CWE IDs."""
    blob = " ".join(
        _text(finding.get(f))
        for f in (
            "description",
            "remediation",
            "control_objective",
            "audit_requirement",
            "proof_of_concept",
        )
    )
    score = 0.0
    if _CVE_RE.search(blob):
        score += 0.25
    if _VERSION_RE.search(blob):
        score += 0.25
    if _PORT_RE.search(blob):
        score += 0.15
    if finding.get("cwe") or "cwe-" in blob.lower():
        score += 0.15
    if finding.get("cvss"):
        score += 0.10
    refs = finding.get("reference")
    if isinstance(refs, (list, tuple)) and len(refs) >= 2:
        score += 0.10
    elif isinstance(refs, str) and len(refs) > 30:
        score += 0.05
    return min(score, 1.0)


def score_finding(finding: Mapping[str, Any]) -> dict:
    """Per-finding score. Returns dict with overall 0-1 + component breakdown + flags."""
    flags: list[str] = []

    # Length coverage per field
    length_scores = {}
    for field in ("description", "remediation", "control_objective", "control_name", "audit_requirement"):
        text = _text(finding.get(field))
        s = _length_score(field, text)
        length_scores[field] = s
        if s < 0.6:
            flags.append(f"short:{field}")
        if text and _has_generic_phrase(text) and len(text) < 150:
            flags.append(f"generic:{field}")

    length_avg = sum(length_scores.values()) / len(length_scores)

    # Remediation tier structure
    rem_tier = _remediation_tier_score(finding.get("remediation"))
    if rem_tier < 0.67:
        flags.append("rem:missing-tiers")

    # Specificity
    specificity = _specificity_bonus(finding)
    if specificity < 0.3:
        flags.append("low-specificity")

    # Composite: weighted
    overall = (
        0.40 * length_avg
        + 0.30 * rem_tier
        + 0.30 * specificity
    )

    return {
        "overall": round(overall, 3),
        "length": round(length_avg, 3),
        "remediation_tiers": round(rem_tier, 3),
        "specificity": round(specificity, 3),
        "flags": flags,
        "id": finding.get("id"),
        "name": finding.get("name"),
    }


def score_report(report: Mapping[str, Any], min_pass: float = 0.65) -> dict:
    """Score all findings in a report. Returns summary dict."""
    findings = report.get("findings") or []
    per_finding = [score_finding(f) for f in findings]
    if not per_finding:
        return {
            "count": 0,
            "mean": 0.0,
            "pass_rate": 0.0,
            "failing": [],
            "per_finding": [],
        }
    mean = sum(p["overall"] for p in per_finding) / len(per_finding)
    failing = [p for p in per_finding if p["overall"] < min_pass]
    return {
        "count": len(per_finding),
        "mean": round(mean, 3),
        "min_pass": min_pass,
        "pass_rate": round(1 - len(failing) / len(per_finding), 3),
        "failing": failing,
        "per_finding": per_finding,
    }


def main() -> None:
    import argparse
    import json
    import sys

    ap = argparse.ArgumentParser(description="Score VAPT report quality")
    ap.add_argument("report", help="Path to generated report JSON")
    ap.add_argument("--min-pass", type=float, default=0.65)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    with open(args.report, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    summary = score_report(data, min_pass=args.min_pass)
    if args.verbose:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        print(
            f"count={summary['count']} mean={summary['mean']} "
            f"pass_rate={summary['pass_rate']} failing={len(summary['failing'])}"
        )
    sys.exit(0 if summary.get("pass_rate", 0) >= 0.8 else 1)


if __name__ == "__main__":
    main()
