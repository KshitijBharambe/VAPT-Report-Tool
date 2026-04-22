import json
import re
from collections.abc import Callable


def _strip_think_blocks(text: str) -> str:
    """Strip <think>...</think> including unclosed blocks (Qwen3, DeepSeek-R1)."""
    text = re.sub(
        r"<think>.*?</think>", "", text, flags=re.IGNORECASE | re.DOTALL
    ).strip()
    text = re.sub(r"<think>.*$", "", text, flags=re.IGNORECASE | re.DOTALL).strip()
    return text


def _extract_json_str(raw_text: str) -> str:
    """Robustly extract a JSON object string from messy LLM output."""
    text = _strip_think_blocks(raw_text.strip())
    text = re.sub(r"```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"```", "", text).strip()

    try:
        json.loads(text)
        return text
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    if start == -1:
        raw_clean = re.sub(
            r"```(?:json)?\s*", "", raw_text, flags=re.IGNORECASE
        ).strip()
        start = raw_clean.find("{")
        if start == -1:
            raise ValueError("No JSON object found in LLM output.")
        text = raw_clean

    depth = 0
    in_string = False
    escape_next = False
    for i, ch in enumerate(text[start:], start):
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"' and not escape_next:
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]

    end = text.rfind("}")
    if end > start:
        return text[start : end + 1]
    raise ValueError("Could not locate a complete JSON object in LLM output.")


def _repair_json(text: str) -> str:
    """Attempt to fix common JSON syntax errors from small LLMs."""
    text = re.sub(r",\s*([}\]])", r"\1", text)
    text = re.sub(r'(")\s*\n(\s*")', r"\1,\n\2", text)
    text = re.sub(r"(})\s*\n(\s*{)", r"\1,\n\2", text)
    text = re.sub(r'(\]|true|false|null|\d)\s*\n(\s*")', r"\1,\n\2", text)
    return text


def _escape_control_chars_in_json_strings(text: str) -> str:
    """Escape bare control chars inside quoted JSON strings."""
    out = []
    in_str = False
    escape_next = False
    for ch in text:
        if escape_next:
            out.append(ch)
            escape_next = False
            continue
        if ch == "\\":
            out.append(ch)
            escape_next = True
            continue
        if ch == '"':
            out.append(ch)
            in_str = not in_str
            continue
        if in_str:
            if ch == "\n":
                out.append("\\n")
                continue
            if ch == "\r":
                out.append("\\r")
                continue
            if ch == "\t":
                out.append("\\t")
                continue
            if ord(ch) < 0x20:
                out.append("\\u" + format(ord(ch), "04x"))
                continue
        out.append(ch)
    return "".join(out)


def safe_parse_json(raw_text: str) -> dict:
    try:
        candidate = _extract_json_str(raw_text)
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            try:
                candidate_escaped = _escape_control_chars_in_json_strings(candidate)
                return json.loads(candidate_escaped)
            except json.JSONDecodeError:
                repaired = _repair_json(candidate)
                try:
                    return json.loads(repaired)
                except json.JSONDecodeError:
                    repaired2 = _repair_json(candidate_escaped)
                    return json.loads(repaired2)
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"Cannot parse LLM output as JSON: {exc}\nFirst 300 chars:\n{raw_text[:300]}"
        )


def validate_json_schema(
    data: dict,
    *,
    report_schema_required: list[str],
    finding_required_fields: list[str],
    severity_colors: dict[str, str],
    infer_severity_from_cvss: Callable[[str], str],
    infer_severity_from_keywords: Callable[[str, str], str],
    fill_missing_fields: Callable[[dict], None],
    prepare_audit_requirement: Callable[[dict], str],
    prepare_proof_of_concept: Callable[[dict], str],
) -> dict:
    int_fields = (
        "total_critical",
        "total_high",
        "total_medium",
        "total_low",
        "total_findings",
    )

    for field in report_schema_required:
        if field not in data:
            data[field] = (
                0
                if field in int_fields
                else ([] if field == "findings" else "[PLACEHOLDER]")
            )

    if not isinstance(data.get("findings"), list):
        data["findings"] = []

    for finding in data["findings"]:
        for field in finding_required_fields:
            if field not in finding or finding[field] in (None, ""):
                finding[field] = "[PLACEHOLDER]"

        sev_raw = str(finding.get("severity", "")).strip()
        sev_map = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
        }

        normalised = sev_map.get(sev_raw.lower(), "")
        if not normalised or normalised not in sev_map.values():
            normalised = infer_severity_from_cvss(finding.get("cvss", ""))
            if not normalised:
                normalised = infer_severity_from_keywords(
                    finding.get("name", ""), finding.get("description", "")
                )
            if not normalised:
                normalised = sev_raw if sev_raw else "Medium"

        finding["severity"] = normalised
        finding["severity_color"] = severity_colors.get(normalised, "#999999")

        fill_missing_fields(finding)
        finding["audit_requirement"] = prepare_audit_requirement(finding)
        finding["proof_of_concept"] = prepare_proof_of_concept(finding)

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for finding in data["findings"]:
        severity = finding.get("severity", "")
        if severity in counts:
            counts[severity] += 1

    data["total_critical"] = counts["Critical"]
    data["total_high"] = counts["High"]
    data["total_medium"] = counts["Medium"]
    data["total_low"] = counts["Low"]
    data["total_findings"] = sum(counts.values())
    return data
