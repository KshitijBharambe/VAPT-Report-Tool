"""Determinism audit.

Run the same scan input N times, diff key fields across runs. Fields that
vary across runs are candidates for tighter prompts or deterministic
templating.

Usage:
  python scratch/determinism_audit.py <scan_file> [--runs 3] [--out report.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

TRACKED_FIELDS = (
    "name",
    "severity",
    "control_objective",
    "control_name",
    "audit_requirement",
    "remediation",
    "recommendation",
)


def _key(f: dict) -> str:
    return (f.get("vuln_id") or f.get("name") or "").strip().lower()


def _stable(v):
    if isinstance(v, dict):
        return json.dumps(v, sort_keys=True, ensure_ascii=False)
    if isinstance(v, list):
        return json.dumps(v, sort_keys=True, ensure_ascii=False)
    return str(v or "").strip()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scan")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    sys.path.insert(0, str(BASE))
    from generate_report import generate

    runs: list[list[dict]] = []
    for i in range(args.runs):
        print(f"Run {i+1}/{args.runs}…")
        data, _raw, _fps = generate(args.scan)
        runs.append(data.get("findings") or [])

    # Tally distinct values per (finding_key, field) across runs
    per_key_field: dict[tuple[str, str], set[str]] = defaultdict(set)
    for findings in runs:
        for f in findings:
            k = _key(f)
            if not k:
                continue
            for field in TRACKED_FIELDS:
                per_key_field[(k, field)].add(_stable(f.get(field)))

    varying: list[dict] = []
    for (k, field), vals in per_key_field.items():
        if len(vals) > 1:
            varying.append({"key": k, "field": field, "distinct_values": len(vals), "samples": list(vals)[:3]})

    total = len(per_key_field) or 1
    print(f"\nVarying fields: {len(varying)} / {total} ({100*len(varying)/total:.1f}%)")
    for v in sorted(varying, key=lambda x: -x["distinct_values"])[:20]:
        print(f"  {v['key']:40s} | {v['field']:20s} | {v['distinct_values']} values")

    report = {"runs": args.runs, "total_fields": total, "varying": varying}
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2, ensure_ascii=False))
        print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
