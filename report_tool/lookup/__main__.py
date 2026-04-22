"""CLI for lookup data stores.

Usage:
  python -m report_tool.lookup cwe-ingest [--url URL | --file path.xml[.zip]]
  python -m report_tool.lookup cwe-stats
  python -m report_tool.lookup cwe-show CWE-79
  python -m report_tool.lookup capec-ingest [--url URL | --file path.xml[.zip]]
  python -m report_tool.lookup capec-stats
  python -m report_tool.lookup capec-show CAPEC-66
  python -m report_tool.lookup capec-for-cwe CWE-89
"""

from __future__ import annotations

import argparse
import json
import sys


def _cmd_cwe_ingest(args) -> int:
    from report_tool.lookup import cwe_catalog

    if args.file:
        n = cwe_catalog.ingest_from_file(args.file)
    else:
        url = args.url or "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
        print(f"Downloading {url} ...", flush=True)
        n = cwe_catalog.ingest_from_url(url)
    print(f"Ingested {n} CWE entries → {cwe_catalog.db_path()}")
    return 0


def _cmd_cwe_stats(_args) -> int:
    from report_tool.lookup import cwe_catalog

    print(f"DB: {cwe_catalog.db_path()}")
    print(f"Entries: {cwe_catalog.count_entries()}")
    return 0


def _cmd_cwe_show(args) -> int:
    from report_tool.lookup.cwe_lookup import fetch_cwe

    rec = fetch_cwe(args.cwe_id)
    if not rec:
        print("Not found")
        return 1
    print(json.dumps(rec, indent=2, ensure_ascii=False))
    return 0


def _cmd_capec_ingest(args) -> int:
    from report_tool.lookup import capec_catalog

    if args.file:
        n = capec_catalog.ingest_from_file(args.file)
    else:
        url = args.url or "https://capec.mitre.org/data/xml/capec_latest.xml"
        print(f"Downloading {url} ...", flush=True)
        n = capec_catalog.ingest_from_url(url)
    print(f"Ingested {n} CAPEC entries → {capec_catalog.db_path()}")
    return 0


def _cmd_capec_stats(_args) -> int:
    from report_tool.lookup import capec_catalog

    print(f"DB: {capec_catalog.db_path()}")
    print(f"Entries: {capec_catalog.count_entries()}")
    return 0


def _cmd_capec_show(args) -> int:
    from report_tool.lookup import capec_catalog

    rec = capec_catalog.get_capec(args.capec_id)
    if not rec:
        print("Not found")
        return 1
    print(json.dumps(rec, indent=2, ensure_ascii=False))
    return 0


def _cmd_capec_for_cwe(args) -> int:
    from report_tool.lookup.capec_lookup import fetch_capec_for_cwe

    rows = fetch_capec_for_cwe(args.cwe_id)
    print(json.dumps(rows, indent=2, ensure_ascii=False))
    return 0


def _cmd_nist_ingest(args) -> int:
    from report_tool.lookup import nist_catalog

    if args.file:
        n = nist_catalog.ingest_from_file(args.file)
    else:
        url = args.url or None
        print(f"Downloading NIST 800-53 catalog ...", flush=True)
        n = nist_catalog.ingest_from_url(url) if url else nist_catalog.ingest_from_url()
    print(f"Ingested {n} NIST controls → {nist_catalog.db_path()}")
    return 0


def _cmd_nist_stats(_args) -> int:
    from report_tool.lookup import nist_catalog

    print(f"DB: {nist_catalog.db_path()}")
    print(f"Entries: {nist_catalog.count_entries()}")
    return 0


def _cmd_nist_show(args) -> int:
    from report_tool.lookup import nist_catalog

    rec = nist_catalog.get_control(args.control_id)
    if not rec:
        print("Not found")
        return 1
    print(json.dumps(rec, indent=2, ensure_ascii=False))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="report_tool.lookup")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ing = sub.add_parser("cwe-ingest", help="Download + parse MITRE CWE XML into SQLite")
    ing.add_argument("--url", default=None)
    ing.add_argument("--file", default=None, help="Local cwec_latest.xml or .zip")

    sub.add_parser("cwe-stats", help="Show CWE DB stats")

    show = sub.add_parser("cwe-show", help="Show merged CWE entry by ID")
    show.add_argument("cwe_id")

    cap_ing = sub.add_parser("capec-ingest", help="Download + parse MITRE CAPEC XML into SQLite")
    cap_ing.add_argument("--url", default=None)
    cap_ing.add_argument("--file", default=None, help="Local capec_latest.xml or .zip")

    sub.add_parser("capec-stats", help="Show CAPEC DB stats")

    cap_show = sub.add_parser("capec-show", help="Show CAPEC entry by ID")
    cap_show.add_argument("capec_id")

    cap_cwe = sub.add_parser("capec-for-cwe", help="List CAPEC patterns for a CWE")
    cap_cwe.add_argument("cwe_id")

    nist_ing = sub.add_parser("nist-ingest", help="Download + parse NIST 800-53 OSCAL JSON into SQLite")
    nist_ing.add_argument("--url", default=None)
    nist_ing.add_argument("--file", default=None, help="Local OSCAL catalog JSON")

    sub.add_parser("nist-stats", help="Show NIST control DB stats")

    nist_show = sub.add_parser("nist-show", help="Show NIST control by ID (e.g. ac-3)")
    nist_show.add_argument("control_id")

    args = ap.parse_args()
    if args.cmd == "cwe-ingest":
        return _cmd_cwe_ingest(args)
    if args.cmd == "cwe-stats":
        return _cmd_cwe_stats(args)
    if args.cmd == "cwe-show":
        return _cmd_cwe_show(args)
    if args.cmd == "capec-ingest":
        return _cmd_capec_ingest(args)
    if args.cmd == "capec-stats":
        return _cmd_capec_stats(args)
    if args.cmd == "capec-show":
        return _cmd_capec_show(args)
    if args.cmd == "capec-for-cwe":
        return _cmd_capec_for_cwe(args)
    if args.cmd == "nist-ingest":
        return _cmd_nist_ingest(args)
    if args.cmd == "nist-stats":
        return _cmd_nist_stats(args)
    if args.cmd == "nist-show":
        return _cmd_nist_show(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
