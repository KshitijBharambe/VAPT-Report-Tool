import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
HISTORY_DIR = ROOT_DIR / "outputs" / "history"
HISTORY_DB_PATH = HISTORY_DIR / "history.sqlite3"
LEGACY_HISTORY_PATH = HISTORY_DIR / "history.json"
LEGACY_MIGRATION_KEY = "legacy_history_migrated"


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS history_entries (
            id TEXT PRIMARY KEY,
            date TEXT NOT NULL DEFAULT '',
            input_name TEXT NOT NULL DEFAULT '',
            source_file TEXT NOT NULL DEFAULT '',
            finding_count INTEGER NOT NULL DEFAULT 0,
            file_name TEXT NOT NULL DEFAULT '',
            report_path TEXT NOT NULL DEFAULT '',
            log_path TEXT NOT NULL DEFAULT '',
            findings_json TEXT NOT NULL DEFAULT '[]',
            analysis_data_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_history_entries_date
        ON history_entries(date DESC, id DESC);
        """
    )


def _get_meta(conn: sqlite3.Connection, key: str) -> str:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    if not row:
        return ""
    return str(row["value"] or "")


def _set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def _safe_json_dumps(value: Any, fallback: str) -> str:
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return fallback


def _safe_json_loads(raw: str, fallback: Any) -> Any:
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return fallback


def _coerce_int(value: Any, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _coerce_entry(entry: dict[str, Any] | None) -> dict[str, Any]:
    raw = entry if isinstance(entry, dict) else {}
    analysis_data = raw.get("analysis_data")
    if not isinstance(analysis_data, dict):
        analysis_data = {}
    findings = raw.get("findings")
    if not isinstance(findings, list):
        findings = analysis_data.get("findings")
    if not isinstance(findings, list):
        findings = []

    return {
        "id": str(raw.get("id") or uuid.uuid4()),
        "date": str(raw.get("date") or ""),
        "input_name": str(raw.get("input_name") or raw.get("source_file") or "").strip(),
        "source_file": str(raw.get("source_file") or "").strip(),
        "finding_count": _coerce_int(raw.get("finding_count"), len(findings)),
        "file_name": str(raw.get("file_name") or "").strip(),
        "report_path": str(raw.get("report_path") or raw.get("output_path") or "").strip(),
        "log_path": str(raw.get("log_path") or "").strip(),
        "findings": findings,
        "analysis_data": analysis_data,
    }


def _write_entry(conn: sqlite3.Connection, entry: dict[str, Any]) -> None:
    normalized = _coerce_entry(entry)
    conn.execute(
        """
        INSERT INTO history_entries(
            id,
            date,
            input_name,
            source_file,
            finding_count,
            file_name,
            report_path,
            log_path,
            findings_json,
            analysis_data_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            date = excluded.date,
            input_name = excluded.input_name,
            source_file = excluded.source_file,
            finding_count = excluded.finding_count,
            file_name = excluded.file_name,
            report_path = excluded.report_path,
            log_path = excluded.log_path,
            findings_json = excluded.findings_json,
            analysis_data_json = excluded.analysis_data_json
        """,
        (
            normalized["id"],
            normalized["date"],
            normalized["input_name"],
            normalized["source_file"],
            normalized["finding_count"],
            normalized["file_name"],
            normalized["report_path"],
            normalized["log_path"],
            _safe_json_dumps(normalized["findings"], "[]"),
            _safe_json_dumps(normalized["analysis_data"], "{}"),
        ),
    )


def _migrate_legacy_history(conn: sqlite3.Connection, legacy_json_path: Path) -> None:
    if _get_meta(conn, LEGACY_MIGRATION_KEY) == "1":
        return

    if legacy_json_path.exists():
        try:
            payload = json.loads(legacy_json_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            payload = []

        if isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    _write_entry(conn, item)

    _set_meta(conn, LEGACY_MIGRATION_KEY, "1")


def _ensure_ready(
    db_path: Path = HISTORY_DB_PATH,
    legacy_json_path: Path = LEGACY_HISTORY_PATH,
) -> sqlite3.Connection:
    conn = _connect(db_path)
    try:
        _ensure_schema(conn)
        _migrate_legacy_history(conn, legacy_json_path)
        conn.commit()
        return conn
    except Exception:
        conn.close()
        raise


def _row_to_entry(row: sqlite3.Row) -> dict[str, Any]:
    findings = _safe_json_loads(row["findings_json"], [])
    if not isinstance(findings, list):
        findings = []
    analysis_data = _safe_json_loads(row["analysis_data_json"], {})
    if not isinstance(analysis_data, dict):
        analysis_data = {}
    return {
        "id": str(row["id"] or ""),
        "date": str(row["date"] or ""),
        "input_name": str(row["input_name"] or ""),
        "source_file": str(row["source_file"] or ""),
        "finding_count": _coerce_int(row["finding_count"], len(findings)),
        "file_name": str(row["file_name"] or ""),
        "report_path": str(row["report_path"] or ""),
        "log_path": str(row["log_path"] or ""),
        "findings": findings,
        "analysis_data": analysis_data,
    }


def append_entry(
    entry: dict[str, Any],
    db_path: Path = HISTORY_DB_PATH,
    legacy_json_path: Path = LEGACY_HISTORY_PATH,
) -> None:
    conn = _ensure_ready(db_path=db_path, legacy_json_path=legacy_json_path)
    try:
        _write_entry(conn, entry)
        conn.commit()
    finally:
        conn.close()


def list_entries(
    db_path: Path = HISTORY_DB_PATH,
    legacy_json_path: Path = LEGACY_HISTORY_PATH,
) -> list[dict[str, Any]]:
    conn = _ensure_ready(db_path=db_path, legacy_json_path=legacy_json_path)
    try:
        rows = conn.execute(
            """
            SELECT
                id,
                date,
                input_name,
                source_file,
                finding_count,
                file_name,
                report_path,
                log_path,
                findings_json,
                analysis_data_json
            FROM history_entries
            ORDER BY
                CASE WHEN date = '' THEN 1 ELSE 0 END,
                date DESC,
                id DESC
            """
        ).fetchall()
        return [_row_to_entry(row) for row in rows]
    finally:
        conn.close()


def get_entry(
    entry_id: str,
    db_path: Path = HISTORY_DB_PATH,
    legacy_json_path: Path = LEGACY_HISTORY_PATH,
) -> dict[str, Any] | None:
    if not str(entry_id or "").strip():
        return None

    conn = _ensure_ready(db_path=db_path, legacy_json_path=legacy_json_path)
    try:
        row = conn.execute(
            """
            SELECT
                id,
                date,
                input_name,
                source_file,
                finding_count,
                file_name,
                report_path,
                log_path,
                findings_json,
                analysis_data_json
            FROM history_entries
            WHERE id = ?
            """,
            (str(entry_id),),
        ).fetchone()
        if not row:
            return None
        return _row_to_entry(row)
    finally:
        conn.close()
