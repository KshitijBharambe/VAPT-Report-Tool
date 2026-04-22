"""SQLite-backed handmade finding corpus + TF-IDF retriever.

Schema is deliberately flat. Embeddings are TF-IDF sparse vectors computed
on demand (corpus is small — hundreds to low thousands of rows).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

_DEFAULT_DB = Path.home() / ".cache" / "sqtk-tools" / "corpus.sqlite"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    severity TEXT,
    status TEXT,
    affected TEXT,
    impact TEXT,
    cves_json TEXT,
    cwes_json TEXT,
    control_objective TEXT,
    control_name TEXT,
    audit_requirement TEXT,
    recommendation TEXT,
    reference TEXT,
    repeat_status TEXT,
    source TEXT
);
CREATE INDEX IF NOT EXISTS idx_name ON findings(name);
CREATE INDEX IF NOT EXISTS idx_source ON findings(source);
"""


@dataclass
class CorpusRecord:
    id: int
    name: str
    severity: str
    control_objective: str
    control_name: str
    audit_requirement: str
    recommendation: str
    reference: str
    cves: list[str]
    cwes: list[str]
    impact: str
    source: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity,
            "control_objective": self.control_objective,
            "control_name": self.control_name,
            "audit_requirement": self.audit_requirement,
            "recommendation": self.recommendation,
            "reference": self.reference,
            "cves": list(self.cves),
            "cwes": list(self.cwes),
            "impact": self.impact,
            "source": self.source,
        }


def _row_to_record(row: sqlite3.Row) -> CorpusRecord:
    return CorpusRecord(
        id=row["id"],
        name=row["name"] or "",
        severity=row["severity"] or "",
        control_objective=row["control_objective"] or "",
        control_name=row["control_name"] or "",
        audit_requirement=row["audit_requirement"] or "",
        recommendation=row["recommendation"] or "",
        reference=row["reference"] or "",
        cves=json.loads(row["cves_json"] or "[]"),
        cwes=json.loads(row["cwes_json"] or "[]"),
        impact=row["impact"] or "",
        source=row["source"] or "",
    )


class CorpusStore:
    """Handmade finding corpus. Thin wrapper over SQLite + in-memory TF-IDF index."""

    def __init__(self, path: Path | str = _DEFAULT_DB):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._index: dict | None = None

    def insert_many(self, findings: Iterable) -> int:
        count = 0
        for f in findings:
            d = f.to_dict() if hasattr(f, "to_dict") else f
            self._conn.execute(
                """INSERT INTO findings
                (name, severity, status, affected, impact, cves_json, cwes_json,
                 control_objective, control_name, audit_requirement,
                 recommendation, reference, repeat_status, source)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    d.get("name", ""),
                    d.get("severity", ""),
                    d.get("status", ""),
                    d.get("affected", ""),
                    d.get("impact", ""),
                    json.dumps(d.get("cves", [])),
                    json.dumps(d.get("cwes", [])),
                    d.get("control_objective", ""),
                    d.get("control_name", ""),
                    d.get("audit_requirement", ""),
                    d.get("recommendation", ""),
                    d.get("reference", ""),
                    d.get("repeat_status", ""),
                    d.get("source", ""),
                ),
            )
            count += 1
        self._conn.commit()
        self._index = None  # invalidate
        return count

    def clear(self) -> None:
        self._conn.execute("DELETE FROM findings")
        self._conn.commit()
        self._index = None

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

    def all(self) -> list[CorpusRecord]:
        rows = self._conn.execute("SELECT * FROM findings").fetchall()
        return [_row_to_record(r) for r in rows]

    def get(self, id_: int) -> CorpusRecord | None:
        row = self._conn.execute("SELECT * FROM findings WHERE id=?", (id_,)).fetchone()
        return _row_to_record(row) if row else None

    # ── Retrieval ─────────────────────────────────────────────────────────

    def _build_index(self) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer

        records = self.all()
        if not records:
            self._index = {"records": [], "vec": None, "mat": None}
            return

        corpus = [
            " ".join(
                [
                    r.name,
                    r.control_name,
                    r.control_objective,
                    r.impact,
                    " ".join(r.cves),
                    " ".join(r.cwes),
                ]
            )
            for r in records
        ]
        vec = TfidfVectorizer(ngram_range=(1, 2), stop_words="english", max_features=8000)
        try:
            mat = vec.fit_transform(corpus)
        except ValueError:
            self._index = {"records": records, "vec": None, "mat": None}
            return
        self._index = {"records": records, "vec": vec, "mat": mat}

    def search(
        self,
        query_text: str,
        *,
        cves: list[str] | None = None,
        cwes: list[str] | None = None,
        top_k: int = 3,
        min_score: float = 0.10,
    ) -> list[tuple[CorpusRecord, float]]:
        """Retrieve top-k most similar handmade findings.

        Boosts matches that share CVE or CWE ids with the query.
        """
        if self._index is None:
            self._build_index()
        idx = self._index or {}
        records = idx.get("records") or []
        if not records:
            return []

        scores = [0.0] * len(records)

        vec = idx.get("vec")
        mat = idx.get("mat")
        if vec is not None and mat is not None and query_text.strip():
            from sklearn.metrics.pairwise import cosine_similarity

            try:
                q = vec.transform([query_text])
                sims = cosine_similarity(q, mat)[0]
                scores = [float(s) for s in sims]
            except ValueError:
                pass

        cve_set = {c.strip().upper() for c in (cves or []) if c}
        cwe_set = {c.strip().upper() for c in (cwes or []) if c}
        for i, r in enumerate(records):
            if cve_set and cve_set & {c.upper() for c in r.cves}:
                scores[i] += 0.25
            if cwe_set and cwe_set & {c.upper() for c in r.cwes}:
                scores[i] += 0.15

        ranked = sorted(enumerate(scores), key=lambda x: x[1], reverse=True)
        out: list[tuple[CorpusRecord, float]] = []
        for i, s in ranked[:top_k]:
            if s < min_score:
                break
            out.append((records[i], s))
        return out

    def close(self) -> None:
        self._conn.close()


_STORE_SINGLETON: CorpusStore | None = None


def load_corpus(path: Path | str = _DEFAULT_DB) -> CorpusStore:
    global _STORE_SINGLETON
    if _STORE_SINGLETON is None or str(_STORE_SINGLETON.path) != str(path):
        _STORE_SINGLETON = CorpusStore(path)
    return _STORE_SINGLETON
