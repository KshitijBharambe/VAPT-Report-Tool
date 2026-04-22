"""NIST SP 800-53 Rev 5 control catalog — ingest + SQLite-backed lookup.

Source: NIST OSCAL JSON catalog (usnistgov/oscal-content). ~1100 controls +
enhancements across 20 families (AC, AU, CM, IA, SC, SI, RA, etc.).

Public entries:
  - ingest_from_url / ingest_from_file
  - get_control(control_id)
  - list_family(family)
"""

from __future__ import annotations

import json
import sqlite3
import time
import urllib.request
from pathlib import Path
from typing import Iterable

_OSCAL_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)
_DB_PATH = Path.home() / ".cache" / "sqtk-tools" / "nist_800_53.sqlite"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS controls (
    id TEXT PRIMARY KEY,
    family TEXT,
    title TEXT,
    label TEXT,
    statement TEXT,
    guidance TEXT,
    parent_id TEXT,
    updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_nist_family ON controls(family);
CREATE INDEX IF NOT EXISTS idx_nist_parent ON controls(parent_id);
"""


def _find_parts(parts: list[dict], name: str) -> str:
    out: list[str] = []
    for p in parts or []:
        if p.get("name") == name and p.get("prose"):
            out.append(p["prose"].strip())
        sub = _find_parts(p.get("parts", []), name)
        if sub:
            out.append(sub)
    return "\n".join(x for x in out if x)


def _flatten_statement(parts: list[dict]) -> str:
    lines: list[str] = []
    for p in parts or []:
        if p.get("name") == "statement":
            prose = p.get("prose", "")
            if prose:
                lines.append(prose.strip())
            for child in p.get("parts", []):
                label = ""
                for prop in child.get("props", []):
                    if prop.get("name") == "label":
                        label = prop.get("value", "")
                prose = child.get("prose", "")
                if prose:
                    lines.append(f"{label} {prose}".strip())
    return "\n".join(lines)


def _walk_controls(group: dict, family: str, parent_id: str = "") -> Iterable[dict]:
    fam = group.get("id", family) if "controls" in group else family
    for ctrl in group.get("controls", []) or []:
        cid = ctrl.get("id", "").upper()
        if not cid:
            continue
        label = ""
        for prop in ctrl.get("props", []):
            if prop.get("name") == "label":
                label = prop.get("value", "")
        record = {
            "id": cid,
            "family": fam.upper(),
            "title": ctrl.get("title", ""),
            "label": label,
            "statement": _flatten_statement(ctrl.get("parts", [])),
            "guidance": _find_parts(ctrl.get("parts", []), "guidance"),
            "parent_id": parent_id,
        }
        yield record
        yield from _walk_controls(ctrl, fam, parent_id=cid)
    for sub in group.get("groups", []) or []:
        yield from _walk_controls(sub, sub.get("id", family))


def parse_oscal(data: dict) -> list[dict]:
    catalog = data.get("catalog", data)
    records: list[dict] = []
    for grp in catalog.get("groups", []) or []:
        fam = grp.get("id", "").upper()
        records.extend(_walk_controls(grp, fam))
    return records


def _download(url: str = _OSCAL_URL, timeout: float = 60.0) -> bytes:
    try:
        import httpx
    except ImportError:
        httpx = None  # type: ignore
    if httpx is not None:
        with httpx.Client(timeout=timeout, follow_redirects=True,
                          headers={"User-Agent": "Sqtk-Tools/NIST-ingest"}) as client:
            resp = client.get(url)
            resp.raise_for_status()
            return resp.content
    req = urllib.request.Request(url, headers={"User-Agent": "Sqtk-Tools/NIST-ingest"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _get_conn(path: Path = _DB_PATH) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def ingest_records(records: Iterable[dict], db_path: Path = _DB_PATH) -> int:
    conn = _get_conn(db_path)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    count = 0
    for r in records:
        conn.execute(
            """INSERT OR REPLACE INTO controls
               (id, family, title, label, statement, guidance, parent_id, updated_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                r["id"],
                r.get("family", ""),
                r.get("title", ""),
                r.get("label", ""),
                r.get("statement", ""),
                r.get("guidance", ""),
                r.get("parent_id", ""),
                now,
            ),
        )
        count += 1
    conn.commit()
    return count


def ingest_from_url(url: str = _OSCAL_URL, db_path: Path = _DB_PATH) -> int:
    payload = _download(url)
    data = json.loads(payload.decode("utf-8"))
    return ingest_records(parse_oscal(data), db_path)


def ingest_from_file(path: Path | str, db_path: Path = _DB_PATH) -> int:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return ingest_records(parse_oscal(data), db_path)


def _row_to_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"].upper() if row["id"] else "",
        "family": row["family"] or "",
        "title": row["title"] or "",
        "label": row["label"] or "",
        "statement": row["statement"] or "",
        "guidance": row["guidance"] or "",
        "parent_id": row["parent_id"] or "",
    }


def get_control(control_id: str, db_path: Path = _DB_PATH) -> dict | None:
    if not db_path.exists() or not control_id:
        return None
    conn = _get_conn(db_path)
    norm = control_id.strip().upper()
    row = conn.execute("SELECT * FROM controls WHERE id=?", (norm,)).fetchone()
    return _row_to_dict(row) if row else None


def list_family(family: str, db_path: Path = _DB_PATH) -> list[dict]:
    if not db_path.exists():
        return []
    conn = _get_conn(db_path)
    rows = conn.execute(
        "SELECT * FROM controls WHERE family=? ORDER BY id", (family.upper(),)
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def count_entries(db_path: Path = _DB_PATH) -> int:
    if not db_path.exists():
        return 0
    conn = _get_conn(db_path)
    return conn.execute("SELECT COUNT(*) FROM controls").fetchone()[0]


def db_path() -> Path:
    return _DB_PATH
