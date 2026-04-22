"""Extract findings from handmade VAPT report docx files.

Handmade reports use 12-13 row tables with a consistent label column.
We detect by label row text, not index — resilient to row reordering.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# Label aliases → canonical field
_LABEL_ALIASES = {
    "affected url /ip": "affected",
    "affected url/ip": "affected",
    "affected url / ip": "affected",
    "vulnerability title / observation": "name",
    "vulnerability title/observation": "name",
    "severity": "severity",
    "status": "status",
    "vulnerability point /impact": "impact",
    "vulnerability point/impact": "impact",
    "cve /cwe": "cve_cwe",
    "cve/cwe": "cve_cwe",
    "control objective": "control_objective",
    "control name": "control_name",
    "audit requirement": "audit_requirement",
    "recommendation": "recommendation",
    "reference": "reference",
    "new or repeat observation": "repeat_status",
}

_CVE_RE = re.compile(r"CVE[\s\-]*\d{4}[\s\-]*\d{3,7}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE[\s\-]*\d{1,5}", re.IGNORECASE)


@dataclass
class CorpusFinding:
    name: str = ""
    severity: str = ""
    status: str = ""
    affected: str = ""
    impact: str = ""
    cves: list[str] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)
    control_objective: str = ""
    control_name: str = ""
    audit_requirement: str = ""
    recommendation: str = ""
    reference: str = ""
    repeat_status: str = ""
    source: str = ""

    def is_valid(self) -> bool:
        return bool(self.name and self.control_objective and self.recommendation)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "severity": self.severity,
            "status": self.status,
            "affected": self.affected,
            "impact": self.impact,
            "cves": list(self.cves),
            "cwes": list(self.cwes),
            "control_objective": self.control_objective,
            "control_name": self.control_name,
            "audit_requirement": self.audit_requirement,
            "recommendation": self.recommendation,
            "reference": self.reference,
            "repeat_status": self.repeat_status,
            "source": self.source,
        }


def _normalize_label(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def _parse_cve_cwe(text: str) -> tuple[list[str], list[str]]:
    cves = [re.sub(r"\s+", "-", m.group().upper().replace("CVE-", "CVE-"))
            for m in _CVE_RE.finditer(text)]
    cves = [re.sub(r"-+", "-", c) for c in cves]
    cwes = [re.sub(r"\s+", "-", m.group().upper()) for m in _CWE_RE.finditer(text)]
    cwes = [re.sub(r"-+", "-", c) for c in cwes]
    return list(dict.fromkeys(cves)), list(dict.fromkeys(cwes))


def _extract_from_table(table, source: str) -> CorpusFinding | None:
    """Parse a single finding table. Returns None if schema doesn't match."""
    finding = CorpusFinding(source=source)
    matched = 0
    for row in table.rows:
        cells = [c.text.strip() for c in row.cells]
        if len(cells) < 2:
            continue
        # Find label cell (any cell that matches a known label)
        label = ""
        value = ""
        for i, cell in enumerate(cells):
            norm = _normalize_label(cell)
            if norm in _LABEL_ALIASES:
                label = _LABEL_ALIASES[norm]
                # Value = last cell distinct from label cell
                for j in range(len(cells) - 1, i, -1):
                    if cells[j].strip() and cells[j].strip() != cell.strip():
                        value = cells[j].strip()
                        break
                break
        if not label or not value:
            continue
        matched += 1
        if label == "name":
            finding.name = value
        elif label == "severity":
            finding.severity = value
        elif label == "status":
            finding.status = value
        elif label == "affected":
            finding.affected = value
        elif label == "impact":
            finding.impact = value
        elif label == "cve_cwe":
            cves, cwes = _parse_cve_cwe(value)
            finding.cves = cves
            finding.cwes = cwes
        elif label == "control_objective":
            finding.control_objective = value
        elif label == "control_name":
            finding.control_name = value
        elif label == "audit_requirement":
            finding.audit_requirement = value
        elif label == "recommendation":
            finding.recommendation = value
        elif label == "reference":
            finding.reference = value
        elif label == "repeat_status":
            finding.repeat_status = value

    # Require minimum label matches so random 2-col tables don't slip through
    if matched < 6:
        return None
    return finding if finding.is_valid() else None


def extract_docx_findings(path: str | Path) -> list[CorpusFinding]:
    """Extract all finding tables from a handmade VAPT docx report."""
    from docx import Document

    doc = Document(str(path))
    source = Path(path).name
    out: list[CorpusFinding] = []
    for table in doc.tables:
        f = _extract_from_table(table, source)
        if f is not None:
            out.append(f)
    return out


def extract_many(paths: Iterable[str | Path]) -> list[CorpusFinding]:
    out: list[CorpusFinding] = []
    for p in paths:
        out.extend(extract_docx_findings(p))
    return out
