"""Full MITRE CAPEC catalog — ingest + SQLite-backed lookup.

Replaces the static snapshot in capec_lookup with the complete MITRE CAPEC
catalog (~550+ attack patterns). Public entries:
  - ingest_from_url / ingest_from_file
  - get_capec(id)
  - get_capecs_for_cwe(cwe_id)
"""

from __future__ import annotations

import io
import json
import re
import sqlite3
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Iterable

_CAPEC_XML_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"
_DB_PATH = Path.home() / ".cache" / "sqtk-tools" / "capec.sqlite"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS capecs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    abstraction TEXT,
    status TEXT,
    likelihood TEXT,
    severity TEXT,
    description TEXT,
    prerequisites TEXT,
    skills_required TEXT,
    resources_required TEXT,
    consequences TEXT,
    mitigations TEXT,
    execution_flow TEXT,
    related_cwes_json TEXT,
    refs_json TEXT,
    updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_capec_name ON capecs(name);

CREATE TABLE IF NOT EXISTS capec_cwe_map (
    capec_id TEXT NOT NULL,
    cwe_id TEXT NOT NULL,
    PRIMARY KEY (capec_id, cwe_id)
);
CREATE INDEX IF NOT EXISTS idx_capec_cwe_cwe ON capec_cwe_map(cwe_id);
"""

_NS_RE = re.compile(r"^\{[^}]+\}")


def _strip_ns(tag: str) -> str:
    return _NS_RE.sub("", tag)


def _clean(text: str | None) -> str:
    if not text:
        return ""
    return " ".join(text.split())


def _flat_text(elem: ET.Element) -> str:
    chunks: list[str] = []
    for t in elem.itertext():
        if t and t.strip():
            chunks.append(t.strip())
    return " ".join(chunks)


def _child_text(elem: ET.Element, tag: str) -> str:
    for child in elem:
        if _strip_ns(child.tag) == tag:
            return _flat_text(child)
    return ""


def _parse_prereqs(elem: ET.Element) -> str:
    out: list[str] = []
    for p in elem.iter():
        if _strip_ns(p.tag) != "Prerequisite":
            continue
        txt = _flat_text(p)
        if txt:
            out.append(txt)
    return " | ".join(out)


def _parse_simple_list(elem: ET.Element, container: str, item: str) -> str:
    out: list[str] = []
    for c in elem.iter():
        if _strip_ns(c.tag) != container:
            continue
        for ch in c:
            if _strip_ns(ch.tag) == item:
                txt = _flat_text(ch)
                if txt:
                    out.append(txt)
    return " | ".join(out)


def _parse_skills(elem: ET.Element) -> str:
    out: list[str] = []
    for s in elem.iter():
        if _strip_ns(s.tag) != "Skill":
            continue
        level = s.attrib.get("Level", "")
        txt = _flat_text(s)
        line = f"[{level}] {txt}" if level else txt
        if line.strip():
            out.append(line)
    return " | ".join(out)


def _parse_consequences(elem: ET.Element) -> str:
    out: list[str] = []
    for cons in elem.iter():
        if _strip_ns(cons.tag) != "Consequence":
            continue
        scopes: list[str] = []
        impacts: list[str] = []
        note = ""
        for child in cons:
            name = _strip_ns(child.tag)
            if name == "Scope" and child.text:
                scopes.append(child.text.strip())
            elif name == "Impact" and child.text:
                impacts.append(child.text.strip())
            elif name == "Note":
                note = _flat_text(child)
        line = f"Scope: {', '.join(scopes)}; Impact: {', '.join(impacts)}"
        if note:
            line += f"; Note: {note}"
        out.append(line)
    return " | ".join(out)


def _parse_mitigations(elem: ET.Element) -> str:
    out: list[str] = []
    for m in elem.iter():
        if _strip_ns(m.tag) != "Mitigation":
            continue
        txt = _flat_text(m)
        if txt:
            out.append(txt)
    return " | ".join(out)


def _parse_execution_flow(elem: ET.Element) -> str:
    out: list[str] = []
    for step in elem.iter():
        if _strip_ns(step.tag) != "Attack_Step":
            continue
        phase = ""
        title = ""
        desc = ""
        for child in step:
            name = _strip_ns(child.tag)
            if name == "Phase" and child.text:
                phase = child.text.strip()
            elif name == "Step_Title" and child.text:
                title = child.text.strip()
            elif name == "Description":
                desc = _flat_text(child)
        line = f"[{phase}] {title}: {desc}".strip(": ").strip()
        if line:
            out.append(line)
    return " | ".join(out)


def _parse_related_cwes(elem: ET.Element) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for r in elem.iter():
        if _strip_ns(r.tag) != "Related_Weakness":
            continue
        cid = r.attrib.get("CWE_ID", "")
        if cid:
            full = f"CWE-{cid}"
            if full not in seen:
                seen.add(full)
                out.append(full)
    return out


def _parse_refs_map(root: ET.Element) -> dict[str, dict]:
    refs: dict[str, dict] = {}
    for r in root.iter():
        if _strip_ns(r.tag) != "Reference":
            continue
        rid = r.attrib.get("Reference_ID", "")
        if not rid:
            continue
        title = ""
        url = ""
        for child in r:
            n = _strip_ns(child.tag)
            if n == "Title" and child.text:
                title = child.text.strip()
            elif n == "URL" and child.text:
                url = child.text.strip()
        refs[rid] = {"title": title, "url": url}
    return refs


def _pattern_refs(elem: ET.Element, ref_map: dict[str, dict]) -> list[dict]:
    out: list[dict] = []
    for r in elem.iter():
        if _strip_ns(r.tag) != "Reference":
            continue
        rid = r.attrib.get("External_Reference_ID", "")
        meta = ref_map.get(rid)
        if meta:
            out.append(meta)
    return out


def parse_capec_xml(xml_bytes: bytes) -> list[dict]:
    """Parse CAPEC XML dump into normalized records."""
    root = ET.fromstring(xml_bytes)
    ref_map = _parse_refs_map(root)
    records: list[dict] = []
    for p in root.iter():
        if _strip_ns(p.tag) != "Attack_Pattern":
            continue
        pid = p.attrib.get("ID")
        if not pid:
            continue
        record = {
            "id": f"CAPEC-{pid}",
            "name": p.attrib.get("Name", ""),
            "abstraction": p.attrib.get("Abstraction", ""),
            "status": p.attrib.get("Status", ""),
            "likelihood": _child_text(p, "Likelihood_Of_Attack"),
            "severity": _child_text(p, "Typical_Severity"),
            "description": _child_text(p, "Description"),
            "prerequisites": _parse_prereqs(p),
            "skills_required": _parse_skills(p),
            "resources_required": _parse_simple_list(p, "Resources_Required", "Resource"),
            "consequences": _parse_consequences(p),
            "mitigations": _parse_mitigations(p),
            "execution_flow": _parse_execution_flow(p),
            "related_cwes": _parse_related_cwes(p),
            "refs": _pattern_refs(p, ref_map),
        }
        records.append(record)
    return records


def _download_xml_bytes(url: str = _CAPEC_XML_URL, timeout: float = 60.0) -> bytes:
    try:
        import httpx
    except ImportError:
        httpx = None  # type: ignore

    if httpx is not None:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "Sqtk-Tools/CAPEC-ingest"},
        ) as client:
            resp = client.get(url)
            resp.raise_for_status()
            payload = resp.content
    else:
        req = urllib.request.Request(url, headers={"User-Agent": "Sqtk-Tools/CAPEC-ingest"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read()
    if payload[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            xml_name = next(n for n in zf.namelist() if n.endswith(".xml"))
            return zf.read(xml_name)
    return payload


def _get_conn(path: Path = _DB_PATH) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def ingest_records(records: Iterable[dict], db_path: Path = _DB_PATH) -> int:
    import time

    conn = _get_conn(db_path)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    count = 0
    for r in records:
        conn.execute(
            """INSERT OR REPLACE INTO capecs
            (id, name, abstraction, status, likelihood, severity, description,
             prerequisites, skills_required, resources_required, consequences,
             mitigations, execution_flow, related_cwes_json, refs_json, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                r["id"],
                r.get("name", ""),
                r.get("abstraction", ""),
                r.get("status", ""),
                r.get("likelihood", ""),
                r.get("severity", ""),
                r.get("description", ""),
                r.get("prerequisites", ""),
                r.get("skills_required", ""),
                r.get("resources_required", ""),
                r.get("consequences", ""),
                r.get("mitigations", ""),
                r.get("execution_flow", ""),
                json.dumps(r.get("related_cwes", [])),
                json.dumps(r.get("refs", [])),
                now,
            ),
        )
        conn.execute("DELETE FROM capec_cwe_map WHERE capec_id=?", (r["id"],))
        for cwe in r.get("related_cwes", []):
            conn.execute(
                "INSERT OR IGNORE INTO capec_cwe_map (capec_id, cwe_id) VALUES (?, ?)",
                (r["id"], cwe),
            )
        count += 1
    conn.commit()
    return count


def ingest_from_url(url: str = _CAPEC_XML_URL, db_path: Path = _DB_PATH) -> int:
    xml_bytes = _download_xml_bytes(url)
    records = parse_capec_xml(xml_bytes)
    return ingest_records(records, db_path)


def ingest_from_file(xml_path: Path | str, db_path: Path = _DB_PATH) -> int:
    data = Path(xml_path).read_bytes()
    if str(xml_path).endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            xml_name = next(n for n in zf.namelist() if n.endswith(".xml"))
            data = zf.read(xml_name)
    records = parse_capec_xml(data)
    return ingest_records(records, db_path)


def _row_to_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"] or "",
        "abstraction": row["abstraction"] or "",
        "status": row["status"] or "",
        "likelihood": row["likelihood"] or "",
        "severity": row["severity"] or "",
        "description": row["description"] or "",
        "prerequisites": row["prerequisites"] or "",
        "skills_required": row["skills_required"] or "",
        "resources_required": row["resources_required"] or "",
        "consequences": row["consequences"] or "",
        "mitigations": row["mitigations"] or "",
        "execution_flow": row["execution_flow"] or "",
        "related_cwes": json.loads(row["related_cwes_json"] or "[]"),
        "refs": json.loads(row["refs_json"] or "[]"),
    }


def get_capec(capec_id: str, db_path: Path = _DB_PATH) -> dict | None:
    if not db_path.exists():
        return None
    conn = _get_conn(db_path)
    norm = capec_id.strip().upper()
    if not norm.startswith("CAPEC-"):
        norm = f"CAPEC-{norm}"
    row = conn.execute("SELECT * FROM capecs WHERE id=?", (norm,)).fetchone()
    return _row_to_dict(row) if row else None


def get_capecs_for_cwe(cwe_id: str, db_path: Path = _DB_PATH) -> list[dict]:
    if not db_path.exists() or not cwe_id:
        return []
    norm = cwe_id.strip().upper()
    if not norm.startswith("CWE-"):
        norm = f"CWE-{norm}"
    conn = _get_conn(db_path)
    rows = conn.execute(
        """SELECT c.* FROM capecs c
           JOIN capec_cwe_map m ON m.capec_id = c.id
           WHERE m.cwe_id = ?
           ORDER BY
             CASE c.likelihood WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 WHEN 'Low' THEN 2 ELSE 3 END,
             CASE c.severity WHEN 'Very High' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END""",
        (norm,),
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def count_entries(db_path: Path = _DB_PATH) -> int:
    if not db_path.exists():
        return 0
    conn = _get_conn(db_path)
    return conn.execute("SELECT COUNT(*) FROM capecs").fetchone()[0]


def db_path() -> Path:
    return _DB_PATH
