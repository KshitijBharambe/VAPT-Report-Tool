"""Quality baseline runner.

Scores a generated report JSON against `quality_baseline.json`. Fails
(non-zero exit) if mean score regresses by more than `--tolerance` (default
0.05) vs the committed baseline. Use `--update` to rewrite the baseline.

Baseline schema:
{
  "<input_key>": {"mean": float, "pass_rate": float, "count": int}
}
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
BASELINE_PATH = BASE / "quality_baseline.json"


def _load_baseline() -> dict:
    if BASELINE_PATH.exists():
        try:
            return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _save_baseline(data: dict) -> None:
    BASELINE_PATH.write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Quality baseline regression gate")
    ap.add_argument("report", help="Path to report JSON to score")
    ap.add_argument("--key", required=True, help="Baseline entry key (e.g. input filename)")
    ap.add_argument("--tolerance", type=float, default=0.05)
    ap.add_argument("--min-pass", type=float, default=0.55)
    ap.add_argument("--update", action="store_true", help="Overwrite baseline with current score")
    args = ap.parse_args()

    sys.path.insert(0, str(BASE))
    from report_tool.quality.scorer import score_report

    data = json.loads(Path(args.report).read_text(encoding="utf-8"))
    summary = score_report(data, min_pass=args.min_pass)
    current = {
        "mean": summary["mean"],
        "pass_rate": summary["pass_rate"],
        "count": summary["count"],
    }

    baseline = _load_baseline()
    prior = baseline.get(args.key)

    if args.update or prior is None:
        baseline[args.key] = current
        _save_baseline(baseline)
        print(f"✅ Baseline {'updated' if prior else 'created'} for {args.key}: {current}")
        return 0

    regression = prior["mean"] - current["mean"]
    if regression > args.tolerance:
        print(
            f"❌ Regression on {args.key}: mean {prior['mean']} → {current['mean']} "
            f"(drop {regression:.3f} > tolerance {args.tolerance})"
        )
        return 1

    print(
        f"✅ OK {args.key}: mean {current['mean']} vs baseline {prior['mean']} "
        f"(Δ {-regression:+.3f})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
