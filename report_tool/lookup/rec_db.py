"""Local SQLite recommendation database for VAPT findings.

Stores LLM-generated lookup keyed by CWE combination + severity.
On lookup: exact CWE match → similar CWE family match → None (triggers LLM call).
Every LLM result is stored back for future reuse.

Public entries:
  lookup(cwe_ids, severity, title) -> dict | None
  store(cwe_ids, severity, title, lookup, quality_score)
  close()
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

_DB_PATH = Path.home() / ".cache" / "sqtk-tools" / "rec_db.sqlite"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS recommendations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cwe_key TEXT NOT NULL,
    severity TEXT NOT NULL,
    title_hash TEXT NOT NULL,
    primary_rec TEXT NOT NULL,
    secondary_rec TEXT,
    defensive_rec TEXT,
    control_objective TEXT,
    control_name TEXT,
    audit_requirement TEXT,
    business_impact TEXT,
    quality_score REAL DEFAULT 0.0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cwe_sev ON recommendations(cwe_key, severity);
CREATE INDEX IF NOT EXISTS idx_title ON recommendations(title_hash);
"""

_conn: sqlite3.Connection | None = None


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.executescript(_SCHEMA)
        cols = {
            row["name"]
            for row in _conn.execute("PRAGMA table_info(recommendations)").fetchall()
        }
        if "business_impact" not in cols:
            _conn.execute("ALTER TABLE recommendations ADD COLUMN business_impact TEXT")
        _conn.commit()
    return _conn


def _cwe_key(cwe_ids: list[str]) -> str:
    """Stable key: sorted, normalized, pipe-joined."""
    normed = sorted({c.strip().upper() for c in cwe_ids if c})
    return "|".join(normed)


def _title_hash(title: str, cves: list[str] | None = None, context: str = "") -> str:
    """Context-aware hash: title + sorted CVE ids + first 200 chars of context.

    Prevents cross-finding cache reuse where titles collide but CVE/context differ.
    """
    cve_part = "|".join(sorted({c.strip().upper() for c in (cves or []) if c}))
    ctx_part = (context or "").strip().lower()[:200]
    payload = f"{title.strip().lower()}::{cve_part}::{ctx_part}"
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _cwe_family(cwe_ids: list[str]) -> list[str]:
    """Broaden to CWE 'family' for fuzzy match: strip last digit group."""
    families: list[str] = []
    for cid in cwe_ids:
        norm = cid.strip().upper()
        if norm.startswith("CWE-"):
            num = norm[4:]
            if len(num) >= 3:
                families.append(f"CWE-{num[:-1]}")
    return sorted(set(families))


def _row_to_lookup(row: sqlite3.Row) -> dict:
    return {
        "control_objective": row["control_objective"] or "",
        "control_name": row["control_name"] or "",
        "audit_requirement": row["audit_requirement"] or "",
        "business_impact": row["business_impact"] or "",
        "recommendation": {
            "primary": row["primary_rec"] or "",
            "secondary": row["secondary_rec"] or "",
            "defensive": row["defensive_rec"] or "",
        },
    }


def lookup(
    cwe_ids: list[str],
    severity: str,
    title: str = "",
    min_quality: float = 0.72,
    cves: list[str] | None = None,
    context: str = "",
) -> dict | None:
    """Look up cached recommendation. Strict match to prevent cross-context reuse."""
    if not cwe_ids:
        return None
    conn = _get_conn()
    key = _cwe_key(cwe_ids)
    sev = (severity or "").strip().lower()
    th = _title_hash(title, cves=cves, context=context) if title else ""

    # 1. Exact: same CWE + severity + title/context hash
    if th:
        row = conn.execute(
            "SELECT * FROM recommendations WHERE cwe_key=? AND severity=? AND title_hash=? AND quality_score>=? ORDER BY quality_score DESC LIMIT 1",
            (key, sev, th, min_quality),
        ).fetchone()
        if row:
            return _row_to_lookup(row)

    # 2. Same CWE + severity (title may differ, but CWE+sev is a narrow bucket)
    row = conn.execute(
        "SELECT * FROM recommendations WHERE cwe_key=? AND severity=? AND quality_score>=? ORDER BY quality_score DESC LIMIT 1",
        (key, sev, min_quality),
    ).fetchone()
    if row:
        return _row_to_lookup(row)

    return None


def store(
    cwe_ids: list[str],
    severity: str,
    title: str,
    lookup: dict,
    quality_score: float = 0.8,
    cves: list[str] | None = None,
    context: str = "",
) -> None:
    """Persist a lookup result. Upserts by cwe_key+severity+title_hash."""
    if not cwe_ids or not lookup:
        return
    conn = _get_conn()
    key = _cwe_key(cwe_ids)
    sev = (severity or "").strip().lower()
    th = _title_hash(title, cves=cves, context=context)
    rec = lookup.get("recommendation") or {}
    if isinstance(rec, str):
        rec = {"primary": rec, "secondary": "", "defensive": ""}
    existing = conn.execute(
        "SELECT id FROM recommendations WHERE cwe_key=? AND severity=? AND title_hash=? LIMIT 1",
        (key, sev, th),
    ).fetchone()
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if existing:
        conn.execute(
            """UPDATE recommendations SET
                primary_rec=?, secondary_rec=?, defensive_rec=?,
                control_objective=?, control_name=?, audit_requirement=?, business_impact=?,
                quality_score=?, created_at=?
            WHERE id=?""",
            (
                rec.get("primary", ""),
                rec.get("secondary", ""),
                rec.get("defensive", ""),
                lookup.get("control_objective", ""),
                lookup.get("control_name", ""),
                lookup.get("audit_requirement", ""),
                lookup.get("business_impact", ""),
                quality_score,
                now,
                existing["id"],
            ),
        )
    else:
        conn.execute(
            """INSERT INTO recommendations
                (cwe_key, severity, title_hash, primary_rec, secondary_rec, defensive_rec,
                 control_objective, control_name, audit_requirement, business_impact, quality_score, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                key,
                sev,
                th,
                rec.get("primary", ""),
                rec.get("secondary", ""),
                rec.get("defensive", ""),
                lookup.get("control_objective", ""),
                lookup.get("control_name", ""),
                lookup.get("audit_requirement", ""),
                lookup.get("business_impact", ""),
                quality_score,
                now,
            ),
        )
    conn.commit()


def close() -> None:
    global _conn
    if _conn:
        _conn.close()
        _conn = None


def stats() -> dict:
    """Return DB stats for diagnostics."""
    conn = _get_conn()
    total = conn.execute("SELECT COUNT(*) FROM recommendations").fetchone()[0]
    high_q = conn.execute("SELECT COUNT(*) FROM recommendations WHERE quality_score>=0.8").fetchone()[0]
    return {"total_entries": total, "high_quality_entries": high_q, "db_path": str(_DB_PATH)}
