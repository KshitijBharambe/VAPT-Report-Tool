"""Full MITRE CWE catalog — ingest + SQLite-backed lookup.

Replaces the 21-entry snapshot in cwe_lookup with the complete MITRE catalog
(~900 entries). Public entry `get_cwe(cwe_id)` returns the same shape the
lookup pipeline already consumes.
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

_CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
_DB_PATH = Path.home() / ".cache" / "sqtk-tools" / "cwe.sqlite"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cwes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    abstraction TEXT,
    status TEXT,
    description TEXT,
    extended_description TEXT,
    consequences TEXT,
    mitigations TEXT,
    detection_methods TEXT,
    related_json TEXT,
    refs_json TEXT,
    updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_cwe_name ON cwes(name);
"""

_NS_RE = re.compile(r"^\{[^}]+\}")


def _strip_ns(tag: str) -> str:
    return _NS_RE.sub("", tag)


def _text_children(elem: ET.Element, tag: str) -> str:
    out: list[str] = []
    for child in elem.iter():
        if _strip_ns(child.tag) == tag and child.text:
            out.append(" ".join(child.text.split()))
    return " ".join(out).strip()


def _clean(text: str | None) -> str:
    if not text:
        return ""
    return " ".join(text.split())


def _collect_flat_text(elem: ET.Element) -> str:
    """Join all descendant text, whitespace-normalized."""
    chunks: list[str] = []
    for t in elem.itertext():
        if t and t.strip():
            chunks.append(t.strip())
    return " ".join(chunks)


def _parse_consequences(elem: ET.Element) -> str:
    out: list[str] = []
    for cons in elem.iter():
        if _strip_ns(cons.tag) != "Consequence":
            continue
        scopes = []
        impacts = []
        note = ""
        for child in cons:
            name = _strip_ns(child.tag)
            if name == "Scope" and child.text:
                scopes.append(child.text.strip())
            elif name == "Impact" and child.text:
                impacts.append(child.text.strip())
            elif name == "Note" and child.text:
                note = _clean(child.text)
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
        phase = ""
        desc = ""
        for child in m:
            name = _strip_ns(child.tag)
            if name == "Phase" and child.text:
                phase = child.text.strip()
            elif name == "Description":
                desc = _collect_flat_text(child)
        line = f"[{phase}] {desc}" if phase else desc
        if line.strip():
            out.append(line)
    return " | ".join(out)


def _parse_detection(elem: ET.Element) -> str:
    out: list[str] = []
    for m in elem.iter():
        if _strip_ns(m.tag) != "Detection_Method":
            continue
        method = ""
        desc = ""
        for child in m:
            name = _strip_ns(child.tag)
            if name == "Method" and child.text:
                method = child.text.strip()
            elif name == "Description":
                desc = _collect_flat_text(child)
        line = f"[{method}] {desc}" if method else desc
        if line.strip():
            out.append(line)
    return " | ".join(out)


def _parse_related(elem: ET.Element) -> list[dict]:
    out: list[dict] = []
    for r in elem.iter():
        if _strip_ns(r.tag) != "Related_Weakness":
            continue
        nature = r.attrib.get("Nature", "")
        cwe_id = r.attrib.get("CWE_ID", "")
        if cwe_id:
            out.append({"nature": nature, "cwe_id": f"CWE-{cwe_id}"})
    return out


def _parse_refs(root: ET.Element) -> dict[str, dict]:
    refs: dict[str, dict] = {}
    for r in root.iter():
        if _strip_ns(r.tag) != "Reference":
            continue
        ref_id = r.attrib.get("Reference_ID", "")
        if not ref_id:
            continue
        title = ""
        url = ""
        for child in r:
            n = _strip_ns(child.tag)
            if n == "Title" and child.text:
                title = child.text.strip()
            elif n == "URL" and child.text:
                url = child.text.strip()
        refs[ref_id] = {"title": title, "url": url}
    return refs


def _weakness_refs(elem: ET.Element, ref_map: dict[str, dict]) -> list[dict]:
    out: list[dict] = []
    for r in elem.iter():
        if _strip_ns(r.tag) != "Reference":
            continue
        rid = r.attrib.get("External_Reference_ID", "")
        meta = ref_map.get(rid)
        if meta:
            out.append(meta)
    return out


def parse_cwe_xml(xml_bytes: bytes) -> list[dict]:
    """Parse a MITRE CWE XML dump into a list of normalized records."""
    root = ET.fromstring(xml_bytes)
    ref_map = _parse_refs(root)
    records: list[dict] = []
    for w in root.iter():
        if _strip_ns(w.tag) != "Weakness":
            continue
        wid = w.attrib.get("ID")
        if not wid:
            continue
        name = w.attrib.get("Name", "")
        abstraction = w.attrib.get("Abstraction", "")
        status = w.attrib.get("Status", "")

        description = ""
        extended = ""
        for child in w:
            tag = _strip_ns(child.tag)
            if tag == "Description":
                description = _collect_flat_text(child)
            elif tag == "Extended_Description":
                extended = _collect_flat_text(child)

        record = {
            "id": f"CWE-{wid}",
            "name": name,
            "abstraction": abstraction,
            "status": status,
            "description": description,
            "extended_description": extended,
            "consequences": _parse_consequences(w),
            "mitigations": _parse_mitigations(w),
            "detection_methods": _parse_detection(w),
            "related": _parse_related(w),
            "refs": _weakness_refs(w, ref_map),
        }
        records.append(record)
    return records


def _download_xml_bytes(url: str = _CWE_XML_URL, timeout: float = 60.0) -> bytes:
    try:
        import httpx  # uses certifi bundle — avoids macOS SSL chain issues
    except ImportError:
        httpx = None  # type: ignore

    if httpx is not None:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "Sqtk-Tools/CWE-ingest"},
        ) as client:
            resp = client.get(url)
            resp.raise_for_status()
            payload = resp.content
    else:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Sqtk-Tools/CWE-ingest"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read()
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        xml_name = next(n for n in zf.namelist() if n.endswith(".xml"))
        return zf.read(xml_name)


def _get_conn(path: Path = _DB_PATH) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def ingest_records(records: Iterable[dict], db_path: Path = _DB_PATH) -> int:
    conn = _get_conn(db_path)
    import time

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    count = 0
    for r in records:
        conn.execute(
            """INSERT OR REPLACE INTO cwes
            (id, name, abstraction, status, description, extended_description,
             consequences, mitigations, detection_methods, related_json, refs_json, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                r["id"],
                r.get("name", ""),
                r.get("abstraction", ""),
                r.get("status", ""),
                r.get("description", ""),
                r.get("extended_description", ""),
                r.get("consequences", ""),
                r.get("mitigations", ""),
                r.get("detection_methods", ""),
                json.dumps(r.get("related", [])),
                json.dumps(r.get("refs", [])),
                now,
            ),
        )
        count += 1
    conn.commit()
    return count


def ingest_from_url(
    url: str = _CWE_XML_URL, db_path: Path = _DB_PATH
) -> int:
    xml_bytes = _download_xml_bytes(url)
    records = parse_cwe_xml(xml_bytes)
    return ingest_records(records, db_path)


def ingest_from_file(xml_path: Path | str, db_path: Path = _DB_PATH) -> int:
    data = Path(xml_path).read_bytes()
    if xml_path.__str__().endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            xml_name = next(n for n in zf.namelist() if n.endswith(".xml"))
            data = zf.read(xml_name)
    records = parse_cwe_xml(data)
    return ingest_records(records, db_path)


def _row_to_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"] or "",
        "abstraction": row["abstraction"] or "",
        "status": row["status"] or "",
        "description": row["description"] or "",
        "extended_description": row["extended_description"] or "",
        "consequences": row["consequences"] or "",
        "mitigations": row["mitigations"] or "",
        "detection_methods": row["detection_methods"] or "",
        "related": json.loads(row["related_json"] or "[]"),
        "refs": json.loads(row["refs_json"] or "[]"),
    }


def get_cwe_from_db(cwe_id: str, db_path: Path = _DB_PATH) -> dict | None:
    if not db_path.exists():
        return None
    conn = _get_conn(db_path)
    row = conn.execute("SELECT * FROM cwes WHERE id=?", (cwe_id.upper(),)).fetchone()
    return _row_to_dict(row) if row else None


def count_entries(db_path: Path = _DB_PATH) -> int:
    if not db_path.exists():
        return 0
    conn = _get_conn(db_path)
    return conn.execute("SELECT COUNT(*) FROM cwes").fetchone()[0]


def db_path() -> Path:
    return _DB_PATH
