"""Build / inspect the handmade VAPT corpus DB.

Usage:
  python -m report_tool.corpus build <docx> [<docx> ...]
  python -m report_tool.corpus stats
  python -m report_tool.corpus search "<query>" [--top-k 3]
  python -m report_tool.corpus clear
"""

from __future__ import annotations

import argparse
import json
import sys

from report_tool.corpus.extractor import extract_docx_findings
from report_tool.corpus.store import load_corpus


def _cmd_build(args) -> int:
    store = load_corpus()
    if args.replace:
        store.clear()
    total = 0
    for path in args.docx:
        findings = extract_docx_findings(path)
        n = store.insert_many(findings)
        print(f"  {path}: +{n}")
        total += n
    print(f"Inserted {total}. Corpus size: {store.count()}")
    return 0


def _cmd_stats(_args) -> int:
    store = load_corpus()
    print(f"DB path: {store.path}")
    print(f"Findings: {store.count()}")
    return 0


def _cmd_search(args) -> int:
    store = load_corpus()
    hits = store.search(args.query, top_k=args.top_k, min_score=0.0)
    for rec, score in hits:
        print(f"[{score:.3f}] {rec.severity or '?':8s} :: {rec.name}")
        if args.verbose:
            print(f"    CO: {rec.control_objective[:200]}")
            print(f"    REC: {rec.recommendation[:200]}")
    return 0


def _cmd_clear(_args) -> int:
    store = load_corpus()
    store.clear()
    print(f"Cleared. Corpus size: {store.count()}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="report_tool.corpus")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="Extract findings from docx files into corpus")
    b.add_argument("docx", nargs="+")
    b.add_argument("--replace", action="store_true", help="Clear before insert")

    sub.add_parser("stats", help="Show corpus stats")

    s = sub.add_parser("search", help="TF-IDF query against corpus")
    s.add_argument("query")
    s.add_argument("--top-k", type=int, default=5)
    s.add_argument("--verbose", "-v", action="store_true")

    sub.add_parser("clear", help="Wipe the corpus DB")

    args = ap.parse_args()
    if args.cmd == "build":
        return _cmd_build(args)
    if args.cmd == "stats":
        return _cmd_stats(args)
    if args.cmd == "search":
        return _cmd_search(args)
    if args.cmd == "clear":
        return _cmd_clear(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
