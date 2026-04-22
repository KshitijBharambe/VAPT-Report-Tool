"""Pure helpers shared by report UI flows."""

from __future__ import annotations

import copy
import json
from datetime import datetime
from pathlib import Path

import generate_report as gr

CONFIG_PATH = "config.json"
FRONT_MATTER_OVERRIDE_KEY = "front_matter_overrides"
SEV_EMOJI = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}


def _clean_report_override_text(value: object) -> str:
    normalized = gr._normalize_report_text(value)
    return normalized if gr._has_meaningful_text(normalized) else ""


def _iter_normalized_override_lines(value: object):
    if isinstance(value, (list, tuple, set)):
        raw_values = value
    else:
        raw_text = _clean_report_override_text(value)
        raw_values = raw_text.splitlines() if raw_text else []

    for raw_value in raw_values:
        normalized_value = gr._normalize_report_text(raw_value)
        if not normalized_value:
            continue
        for line in normalized_value.splitlines():
            yield line


def _strip_objective_bullet(value: object) -> str:
    cleaned = _clean_report_override_text(value)
    if not cleaned:
        return ""
    for prefix in ("- ", "* ", "• "):
        if cleaned.startswith(prefix):
            return cleaned[len(prefix) :].strip()
    return cleaned


def _normalize_objectives_override(value: object) -> list[str]:
    objectives = []
    for line in _iter_normalized_override_lines(value):
        cleaned_line = _strip_objective_bullet(line)
        if cleaned_line:
            objectives.append(cleaned_line)
    return objectives


def apply_report_level_overrides(
    composed_data: dict,
    override_source: dict | None = None,
) -> dict:
    overridden = copy.deepcopy(composed_data or {})
    source = override_source or composed_data or {}
    overrides = dict(source.get(FRONT_MATTER_OVERRIDE_KEY) or {})

    introduction_overview = _clean_report_override_text(
        overrides.get("introduction_overview")
    )
    if introduction_overview:
        overridden["introduction_overview"] = introduction_overview

    introduction_scope_bridge = _clean_report_override_text(
        overrides.get("introduction_scope_bridge")
    )
    if introduction_scope_bridge:
        overridden["introduction_scope_bridge"] = introduction_scope_bridge

    objectives = _normalize_objectives_override(overrides.get("objectives"))
    if objectives:
        overridden["objectives"] = list(objectives)
        narrative_slots = dict(overridden.get("narrative_slots") or {})
        narrative_slots["objectives"] = list(objectives)
        overridden["narrative_slots"] = narrative_slots

    return overridden


def build_composed_preview(data: dict) -> dict:
    preview_source = copy.deepcopy(data or {})
    composed = gr.compose_report_narrative(preview_source, refresh=True)
    return apply_report_level_overrides(composed, preview_source)


def load_config_safe(config_path: str = CONFIG_PATH) -> dict:
    try:
        return gr.load_config(config_path)
    except Exception:
        return {}


def save_config(cfg: dict, config_path: str = CONFIG_PATH) -> bool:
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        return True
    except Exception:
        return False


def list_docx_templates() -> list:
    templates = [f.name for f in Path(".").glob("*.docx")]
    return templates if templates else ["template.docx"]


def list_output_files(output_dir: str) -> list:
    p = Path(output_dir)
    if not p.exists():
        return []
    files = []
    for f in sorted(p.glob("*.docx"), key=lambda x: x.stat().st_mtime, reverse=True):
        stat = f.stat()
        files.append(
            {
                "name": f.name,
                "size": round(stat.st_size / 1024, 1),
                "mtime": datetime.fromtimestamp(stat.st_mtime).strftime(
                    "%d %b %Y %H:%M"
                ),
                "path": str(f),
            }
        )
    return files


def list_log_files(log_dir: str) -> list:
    p = Path(log_dir)
    if not p.exists():
        return []
    files = []
    log_files = list(p.glob("*_run_log.json")) + list(p.glob("*_raw_llm_response.json"))
    for f in sorted(log_files, key=lambda x: x.stat().st_mtime, reverse=True):
        stat = f.stat()
        ts_raw = (
            f.name.replace("_run_log.json", "").replace("_raw_llm_response.json", "")
        )
        try:
            ts_dt = datetime.strptime(ts_raw, "%Y%m%d_%H%M%S_%f")
        except Exception:
            try:
                ts_dt = datetime.strptime(ts_raw, "%Y%m%d_%H%M%S")
            except Exception:
                ts_dt = None
        if ts_dt is not None:
            label = ts_dt.strftime("%d %b %Y · %H:%M")
        else:
            label = ts_raw
        files.append(
            {
                "name": f.name,
                "label": label,
                "size": round(stat.st_size / 1024, 1),
                "mtime": datetime.fromtimestamp(stat.st_mtime).strftime(
                    "%d %b %Y %H:%M"
                ),
                "path": str(f),
            }
        )
    return files


def load_log_data(path: str) -> dict:
    import re

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    if isinstance(raw, dict) and isinstance(raw.get("events"), list):
        return {
            "raw": json.dumps(raw, indent=2, ensure_ascii=False),
            "parsed": raw,
            "events": raw.get("events", []),
        }
    text = raw.get("raw_response", "")
    parsed = None
    try:
        candidate = gr._extract_json_str(text)
        parsed = json.loads(candidate)
    except Exception:
        pass
    if parsed is None:
        try:
            cleaned = re.sub(
                r"<think>.*?</think>", "", text, flags=re.IGNORECASE | re.DOTALL
            ).strip()
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
            cleaned = re.sub(r"\s*```$", "", cleaned).strip()
            start = cleaned.find("{")
            end = cleaned.rfind("}")
            if start != -1 and end > start:
                parsed = json.loads(cleaned[start : end + 1])
        except Exception:
            parsed = None
    return {"raw": text, "parsed": parsed}


def reset_session(session_state: dict | None = None) -> None:
    """Reset a mutable session_state mapping to stage 0.

    Kept for compatibility with older UI flows.
    """
    target = session_state if session_state is not None else {}
    for key in tuple(target):
        del target[key]
    target["stage"] = 0


def blank_finding(index: int) -> dict:
    return {
        "id": f"{index:03d}",
        "name": "[New Finding]",
        "severity": "Medium",
        "cvss": "[PLACEHOLDER]",
        "cve": "[INSUFFICIENT DATA]",
        "affected_assets": "[PLACEHOLDER]",
        "description": "[PLACEHOLDER]",
        "business_impact": "[PLACEHOLDER]",
        "proof_of_concept": "[PLACEHOLDER]",
        "remediation": "[PLACEHOLDER]",
        "category": "[PLACEHOLDER]",
        "remediation_status": "Open",
        "risk_status": "Open",
        "observation": "New",
        "repeat_status": "New",
        "control_objective": "[PLACEHOLDER]",
        "control_name": "[PLACEHOLDER]",
        "audit_requirement": "[PLACEHOLDER]",
        "reference": "OWASP Top 10",
        "severity_color": "#FF8C00",
    }


def normalize_severity(value: str) -> str:
    sev_map = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }
    return sev_map.get(str(value or "").strip().lower(), "Medium")


def recalculate_totals(data: dict) -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for finding in data.get("findings", []):
        sev = normalize_severity(finding.get("severity", ""))
        if sev in counts:
            counts[sev] += 1
    data["total_critical"] = counts["Critical"]
    data["total_high"] = counts["High"]
    data["total_medium"] = counts["Medium"]
    data["total_low"] = counts["Low"]
    data["total_findings"] = sum(counts.values())
    return data
