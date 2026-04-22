"""Cloud LLM lookup via OpenRouter (OpenAI-compatible API).

Public entry: lookup_finding(finding, config) -> dict
Returns merged finding with control_objective, control_name, tiered recommendation, references.
All outbound payloads gated by privacy.assert_safe_for_egress.

Pipeline per finding:
  1. Check local rec_db (skip LLM call if cached)
  2. CVE lookup → NVD (CVSS, severity, refs)
  3. EPSS lookup → exploitation probability
  4. CWE lookup → snapshot + MITRE
  5. CAPEC lookup → attack patterns
  6. Framework mapping → NIST 800-53, PCI-DSS, OWASP WSTG, ISO 27001, SANS Top 25
  7. Cloud LLM lookup (batched) with full context
  8. Store result back to rec_db
"""

from __future__ import annotations

import json
import os
from inspect import Parameter, signature
from typing import Any

import httpx

from report_core.privacy import (
    ClientDataInternetEgressError,
    EgressViolation,
    assert_safe_for_egress,
    raise_client_data_egress_error,
    restore_placeholders,
    sanitize_value_for_egress,
)
from report_tool.run_logging import append_run_log_event, build_llm_event
from report_tool.lookup import rec_db
from report_tool.lookup.capec_lookup import fetch_capec_for_cwes
from report_tool.lookup.cve_lookup import extract_cve_ids, fetch_cve
from report_tool.lookup.cwe_lookup import extract_cwe_ids, fetch_cwe
from report_tool.lookup.epss_lookup import epss_label, fetch_epss_batch
from report_tool.lookup.framework_mapping import get_merged_frameworks
from report_tool.lookup.prompts import (
    LOOKUP_BATCH_SYSTEM_PROMPT,
    LOOKUP_BATCH_USER_TEMPLATE,
    LOOKUP_SYSTEM_PROMPT,
    LOOKUP_USER_TEMPLATE,
)

BATCH_SIZE = 5
_MAX_BATCH_DESCRIPTION_CHARS = 900
_MAX_STYLE_EXAMPLE_CHARS = 900
_MAX_CONTROL_CONTEXT_CHARS = 220
_PLACEHOLDER_TEXT = {"", "[insufficient data]", "[placeholder]", "n/a", "none", "nan"}

_CORPUS_DISABLED = os.environ.get("SQTK_DISABLE_CORPUS_RAG") == "1"


def _callback_positional_arity(callback) -> int | None:
    try:
        params = signature(callback).parameters.values()
    except (TypeError, ValueError):
        return 3
    if any(param.kind == Parameter.VAR_POSITIONAL for param in params):
        return None
    return sum(
        1
        for param in params
        if param.kind in (Parameter.POSITIONAL_ONLY, Parameter.POSITIONAL_OR_KEYWORD)
    )


def _emit_progress(on_progress, current, total, message="", detail=None) -> None:
    if not on_progress:
        return
    arity = _callback_positional_arity(on_progress)
    payload = [current, total, message]
    if detail is not None and (arity is None or arity >= 4):
        payload.append(detail)
    try:
        on_progress(*payload[:arity] if arity is not None else payload)
    except Exception:
        pass


def _short_progress_label(finding: dict) -> str:
    name = str(
        finding.get("name")
        or finding.get("short_name")
        or "[Unnamed Vulnerability]"
    ).strip()
    if len(name) > 90:
        name = name[:87].rstrip() + "..."
    return name


def _build_cloud_lookup_message(
    current: int, total: int, active_items: list[str]
) -> str:
    if not active_items:
        return f"Cloud lookup {current}/{total}"
    if len(active_items) == 1:
        return f"Cloud lookup {current}/{total}: {active_items[0]}"
    return (
        f"Cloud lookup {current}-{min(total, current + len(active_items) - 1)}/{total}: "
        + "; ".join(active_items)
    )


def _build_fewshot_block(
    finding: dict,
    cve_ids: list[str],
    cwe_ids: list[str],
    top_k: int = 1,
) -> str:
    """Retrieve handmade analogs from the corpus and format as few-shot examples.

    Returns empty string if corpus is empty, disabled, or no match above threshold.
    """
    if _CORPUS_DISABLED:
        return ""
    try:
        from report_tool.corpus import load_corpus
    except ImportError:
        return ""
    try:
        store = load_corpus()
        if store.count() == 0:
            return ""
    except Exception:
        return ""

    query = " ".join(
        [
            str(finding.get("name", "")),
            str(finding.get("description", ""))[:500],
        ]
    )
    try:
        hits = store.search(
            query, cves=cve_ids, cwes=cwe_ids, top_k=top_k, min_score=0.10
        )
    except Exception:
        return ""
    if not hits:
        return ""

    parts = [
        "",
        "REFERENCE EXAMPLES from prior handmade reports (match house style exactly):",
    ]
    for rec, score in hits:
        recommendation_preview = rec.recommendation[:400].strip()
        parts.append(
            f"- Example (similarity {score:.2f}):\n"
            f"    title: {rec.name[:120]}\n"
            f"    control_objective: {rec.control_objective[:220]}\n"
            f"    control_name: {rec.control_name[:80]}\n"
            f"    audit_requirement: {rec.audit_requirement[:220]}\n"
            f"    recommendation: {recommendation_preview}"
        )
    parts.append(
        "Use these as style/phrasing references. Do NOT copy verbatim — adapt to the "
        "current finding's specifics (ports, versions, CVEs, hosts)."
    )
    return "\n".join(parts)[:_MAX_STYLE_EXAMPLE_CHARS]


_OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


def _resolve_api_key(cfg: dict) -> str:
    # API key must come from session/request payload only — no environment variable fallback
    return cfg.get("api_key") or ""


def _fmt_list(items: list) -> str:
    return ", ".join(str(i) for i in items) if items else "none"


def _trim_text(value: str, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def _fmt_capec(patterns: list[dict]) -> str:
    if not patterns:
        return "none"
    parts = []
    for p in patterns:
        parts.append(
            f"{p.get('id','')} - {p.get('name','')} (likelihood: {p.get('likelihood','')})"
        )
    return "; ".join(parts)


def _fmt_epss(epss_map: dict[str, dict], cve_ids: list[str]) -> str:
    if not epss_map or not cve_ids:
        return "unknown"
    parts = []
    for cid in cve_ids:
        e = epss_map.get(cid.upper())
        if e:
            score = e.get("epss", 0)
            label = epss_label(score)
            pct = round(score * 100, 2)
            parts.append(f"{cid}: {pct}% ({label})")
    return "; ".join(parts) if parts else "unknown"


def _build_user_content(
    finding: dict,
    cve_data: list[dict],
    cwe_data: list[dict],
    epss_map: dict[str, dict],
    capec_patterns: list[dict],
    frameworks: dict,
) -> str:
    cve_ids = [c.get("id", "") for c in cve_data if c.get("id")]
    cwe_ids_list = [c.get("id", "") for c in cwe_data if c.get("id")]
    cwe_ctx_lines = []
    for c in cwe_data:
        if c.get("control_objective"):
            cwe_ctx_lines.append(
                f"{c['id']} ({c.get('name','')}): {c['control_objective']}"
            )
    cwe_context = " | ".join(cwe_ctx_lines) or "none"
    cvss = ""
    if cve_data:
        scores = [str(c.get("cvss")) for c in cve_data if c.get("cvss") is not None]
        cvss = ", ".join(scores) or "unknown"
    sans_rank = frameworks.get("sans_top25_rank")
    sans_str = f"#{sans_rank} (high priority)" if sans_rank else "not ranked"
    content = LOOKUP_USER_TEMPLATE.format(
        title=finding.get("name", ""),
        severity=finding.get("severity", ""),
        cves=_fmt_list(cve_ids) or finding.get("cve", "") or "none",
        cwes=_fmt_list(cwe_ids_list) or "none",
        description=finding.get("description", ""),
        cwe_context=cwe_context,
        cvss=cvss or "unknown",
        epss=_fmt_epss(epss_map, cve_ids),
        capec=_fmt_capec(capec_patterns),
        owasp_top10=frameworks.get("owasp_top10") or "not mapped",
        owasp_api_top10=frameworks.get("owasp_api_top10") or "not mapped",
        sans_rank=sans_str,
        nist_controls=_fmt_list(frameworks.get("nist_800_53", [])),
        pci_reqs=_fmt_list(frameworks.get("pci_dss", [])),
        wstg=_fmt_list(frameworks.get("owasp_wstg", [])),
        iso_controls=_fmt_list(frameworks.get("iso_27001", [])),
    )
    fewshot = _build_fewshot_block(finding, cve_ids, cwe_ids_list)
    if fewshot:
        content = content + "\n\n" + fewshot
    return content


def _call_openrouter(
    messages: list[dict],
    cfg: dict,
    timeout: float = 60.0,
    task_type: str = "lookup",
    log_label: str = "cloud_lookup",
    request_original: str = "",
    request_sent: str = "",
) -> str:
    api_key = _resolve_api_key(cfg)
    if not api_key:
        raise RuntimeError(
            "OpenRouter API key missing from the current session. Provide it in the UI before running analysis."
        )
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/sqtk-tools/report-tool",
        "X-Title": "Sqtk VAPT Report Tool",
    }
    task_models = cfg.get("task_models") or {}
    model_id = (
        task_models.get(task_type)
        or task_models.get("lookup")
        or cfg.get("lookup_model")
        or cfg.get("model")
    )
    if not model_id:
        raise RuntimeError(
            "OpenRouter model id missing. Set llm.model in config.json or pass a model from the UI."
        )
    payload = {
        "model": model_id,
        "messages": messages,
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }
    sanitized_payload, restore_map = sanitize_value_for_egress(payload)
    try:
        assert_safe_for_egress(sanitized_payload)
    except EgressViolation as exc:
        raise_client_data_egress_error(
            "structured lookup enrichment",
            "OpenRouter",
            f"Sanitization could not safely remove all client data ({exc}).",
        )
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(_OPENROUTER_URL, headers=headers, json=sanitized_payload)
        resp.raise_for_status()
        data = resp.json()
    raw_text = data["choices"][0]["message"]["content"]
    restored_text = restore_placeholders(raw_text, restore_map)

    append_run_log_event(
        {
            "_run_log_path": cfg.get("_run_log_path"),
            "paths": cfg.get("paths", {}),
            "llm": {
                "provider": "openrouter",
                "model": model_id,
            },
        },
        "llm_interaction",
        build_llm_event(
            log_label=log_label,
            task_type=task_type,
            attempt=1,
            config={
                "llm": {
                    "provider": "openrouter",
                    "model": model_id,
                }
            },
            request_payload=sanitized_payload,
            user_content_original=request_original
            or json.dumps(messages, ensure_ascii=False),
            user_content_sent=request_sent
            or json.dumps(
                (sanitized_payload.get("messages") or messages),
                ensure_ascii=False,
            ),
            response_received_raw=raw_text,
            response_restored=restored_text,
        ),
    )
    return restored_text


def _parse_lookup(raw: str) -> dict | None:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}")
        if start == -1 or end <= start:
            return None
        try:
            data = json.loads(raw[start : end + 1])
        except json.JSONDecodeError:
            return None
    if not isinstance(data, dict):
        return None
    business_impact = str(data.get("business_impact") or "").strip()
    data["business_impact"] = business_impact
    rec = data.get("recommendation")
    if isinstance(rec, str):
        data["recommendation"] = {"primary": rec, "secondary": "", "defensive": ""}
    elif not isinstance(rec, dict):
        data["recommendation"] = {"primary": "", "secondary": "", "defensive": ""}
    refs = data.get("reference")
    if isinstance(refs, str):
        data["reference"] = [{"title": refs, "url": ""}]
    elif not isinstance(refs, list):
        data["reference"] = []
    return data


def _lookup_cves(finding: dict) -> list[dict]:
    blob = " ".join(
        str(finding.get(field) or "")
        for field in ("cve", "description", "proof_of_concept", "reference", "name")
    )
    ids = extract_cve_ids(blob)
    out: list[dict] = []
    for cid in ids[:3]:
        data = fetch_cve(cid)
        if data:
            out.append(data)
    return out


def _collect_cwe_ids(finding: dict, cve_data: list[dict]) -> list[str]:
    cwes: list[str] = []
    for c in cve_data:
        for cwe in c.get("cwes", []):
            if cwe not in cwes:
                cwes.append(cwe)
    for cwe in extract_cwe_ids(
        " ".join(
            [
                finding.get("cve", "") or "",
                finding.get("description", "") or "",
                finding.get("category", "") or "",
                finding.get("proof_of_concept", "") or "",
                str(finding.get("reference", "") or ""),
                finding.get("name", "") or "",
            ]
        )
    ):
        if cwe not in cwes:
            cwes.append(cwe)
    return cwes


def _build_deterministic_refs(cve_data: list[dict], cwe_data: list[dict]) -> list[dict]:
    refs: list[dict] = []
    for c in cve_data:
        refs.append(
            {
                "title": f"NVD Advisory: {c['id']}",
                "url": f"https://nvd.nist.gov/vuln/detail/{c['id']}",
            }
        )
        for r in c.get("references", [])[:2]:
            url = r.get("url")
            if url:
                refs.append({"title": url, "url": url})
    for w in cwe_data:
        wid = w.get("id", "")
        num = wid.replace("CWE-", "")
        if num:
            refs.append(
                {
                    "title": f"MITRE {wid}: {w.get('name','')}".strip(": "),
                    "url": f"https://cwe.mitre.org/data/definitions/{num}.html",
                }
            )
    seen: set[str] = set()
    unique: list[dict] = []
    for r in refs:
        key = r.get("url", "")
        if key and key not in seen:
            seen.add(key)
            unique.append(r)
    return unique[:8]


def _merge_refs(cloud_refs: list[dict], det_refs: list[dict]) -> list[dict]:
    seen: set[str] = set()
    merged: list[dict] = []
    for r in list(det_refs) + list(cloud_refs):
        if not isinstance(r, dict):
            continue
        url = (r.get("url") or "").strip()
        title = (r.get("title") or url).strip()
        key = url or title
        if not key or key in seen:
            continue
        seen.add(key)
        merged.append({"title": title, "url": url})
    return merged[:10]


def _already_resolved(finding: dict) -> bool:
    rec = finding.get("recommendation")
    ref = finding.get("reference")
    rec_tiered = isinstance(rec, dict) and bool(rec.get("primary"))
    ref_list = isinstance(ref, list) and len(ref) > 0
    return rec_tiered and ref_list


def _quality_score(lookup_data: dict) -> float:
    """Heuristic quality score 0–1 based on recommendation substance."""
    rec = lookup_data.get("recommendation") or {}
    if not isinstance(rec, dict):
        return 0.0
    score = 0.0
    for tier in ("primary", "secondary", "defensive"):
        text = rec.get(tier, "") or ""
        if len(text) > 80:
            score += 0.25
        elif len(text) > 30:
            score += 0.1
    if (
        lookup_data.get("control_objective")
        and len(lookup_data["control_objective"]) > 50
    ):
        score += 0.15
    if (
        lookup_data.get("audit_requirement")
        and len(lookup_data["audit_requirement"]) > 50
    ):
        score += 0.1
    if (
        lookup_data.get("business_impact")
        and len(lookup_data["business_impact"]) > 60
    ):
        score += 0.1
    return min(score, 1.0)


def _recommendation_to_remediation(rec) -> str:
    if not isinstance(rec, dict):
        return ""
    lines = []
    for key in ("primary", "secondary", "defensive"):
        text = str(rec.get(key) or "").strip()
        if text:
            lines.append(text)
    return "\n".join(lines)


def lookup_finding(finding: dict, cloud_cfg: dict) -> dict:
    """Enrich a single finding. Checks rec_db first, then LLM. Idempotent."""
    if _already_resolved(finding):
        return dict(finding)
    result = dict(finding)
    cve_data = _lookup_cves(finding)
    cwe_ids = _collect_cwe_ids(finding, cve_data)
    cwe_data = [fetch_cwe(cid) for cid in cwe_ids]
    cwe_data = [c for c in cwe_data if c]

    # Deterministic baseline from CWE snapshot
    if cwe_data:
        primary_cwe = cwe_data[0]
        result.setdefault("control_objective", primary_cwe.get("control_objective", ""))
        result.setdefault("control_name", primary_cwe.get("control_name", ""))
        if cwe_ids:
            result["cwe"] = ", ".join(cwe_ids)
    if cve_data:
        first_cve = cve_data[0]
        if first_cve.get("cvss") is not None:
            result["cvss"] = str(first_cve["cvss"])
        if first_cve.get("severity"):
            result.setdefault("severity", first_cve["severity"].title())
        if first_cve.get("description") and str(result.get("description") or "").strip().lower() in _PLACEHOLDER_TEXT:
            result["description"] = first_cve["description"]

    deterministic_refs = _build_deterministic_refs(cve_data, cwe_data)

    # Check local rec_db before LLM call
    _cves = [c.get("id", "") for c in cve_data if c.get("id")]
    _ctx = str(finding.get("description", "") or "")
    cached = rec_db.lookup(
        cwe_ids,
        finding.get("severity", ""),
        finding.get("name", ""),
        cves=_cves,
        context=_ctx,
    )
    if cached:
        for key in ("control_objective", "control_name", "audit_requirement"):
            if cached.get(key):
                result[key] = cached[key]
        if cached.get("business_impact"):
            result["business_impact"] = cached["business_impact"]
        if isinstance(cached.get("recommendation"), dict):
            result["recommendation"] = cached["recommendation"]
            result["remediation"] = _recommendation_to_remediation(
                cached["recommendation"]
            )
        result["reference"] = _merge_refs([], deterministic_refs)
        return result

    cloud_out: dict | None = None
    if cloud_cfg.get("enabled", False):
        cve_ids_list = [c.get("id", "") for c in cve_data if c.get("id")]
        epss_map = fetch_epss_batch(cve_ids_list) if cve_ids_list else {}
        capec_patterns = fetch_capec_for_cwes(cwe_ids)
        frameworks = get_merged_frameworks(cwe_ids)
        user_content = _build_user_content(
            finding, cve_data, cwe_data, epss_map, capec_patterns, frameworks
        )
        messages = [
            {"role": "system", "content": LOOKUP_SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ]
        try:
            raw = _call_openrouter(messages, cloud_cfg, task_type="lookup_critical")
            cloud_out = _parse_lookup(raw)
        except ClientDataInternetEgressError:
            raise
        except (EgressViolation, httpx.HTTPError, RuntimeError, KeyError):
            cloud_out = None

    if cloud_out:
        for key in (
            "control_objective",
            "control_name",
            "audit_requirement",
            "business_impact",
        ):
            val = cloud_out.get(key)
            if val:
                result[key] = val
        if isinstance(cloud_out.get("recommendation"), dict):
            result["recommendation"] = cloud_out["recommendation"]
            result["remediation"] = _recommendation_to_remediation(
                cloud_out["recommendation"]
            )
        cloud_refs = cloud_out.get("reference") or []
        result["reference"] = _merge_refs(cloud_refs, deterministic_refs)
        # Store to rec_db for future reuse
        qs = _quality_score(cloud_out)
        rec_db.store(
            cwe_ids,
            finding.get("severity", ""),
            finding.get("name", ""),
            cloud_out,
            qs,
            cves=_cves,
            context=_ctx,
        )
    else:
        rec_existing = result.get("recommendation")
        if isinstance(rec_existing, str) and rec_existing:
            result["recommendation"] = {
                "primary": rec_existing,
                "secondary": "",
                "defensive": "",
            }
        elif not isinstance(rec_existing, dict):
            remediation = finding.get("remediation", "") or ""
            result["recommendation"] = {
                "primary": remediation,
                "secondary": "",
                "defensive": "",
            }
        result["remediation"] = _recommendation_to_remediation(
            result.get("recommendation")
        )
        result["reference"] = _merge_refs([], deterministic_refs)

    return result


def _prepare_batch_payload(
    finding: dict,
    key: str,
    cve_data: list[dict],
    cwe_data: list[dict],
    epss_map: dict[str, dict],
    capec_patterns: list[dict],
    frameworks: dict,
) -> tuple[dict, dict]:
    cve_ids = [c.get("id", "") for c in cve_data if c.get("id")]
    cwe_entries = [
        {
            "id": c.get("id", ""),
            "name": _trim_text(c.get("name", ""), 120),
            "control_objective": _trim_text(
                c.get("control_objective", ""), _MAX_CONTROL_CONTEXT_CHARS
            ),
        }
        for c in cwe_data
    ][:2]
    cvss_scores = [c.get("cvss") for c in cve_data if c.get("cvss") is not None]
    sans_rank = frameworks.get("sans_top25_rank")
    cwe_id_list = [c.get("id", "") for c in cwe_entries if c.get("id")]
    payload = {
        "key": key,
        "title": _trim_text(finding.get("name", ""), 180),
        "severity": finding.get("severity", ""),
        "description": _trim_text(
            finding.get("description", ""), _MAX_BATCH_DESCRIPTION_CHARS
        ),
        "cves": cve_ids[:3],
        "cwes": cwe_entries,
        "cvss": cvss_scores[:3],
        "epss": _fmt_epss(epss_map, cve_ids[:3]),
        "capec": _trim_text(_fmt_capec(capec_patterns[:2]), 240),
        "owasp_top10": frameworks.get("owasp_top10") or "not mapped",
        "owasp_api_top10": frameworks.get("owasp_api_top10") or "not mapped",
        "sans_top25_rank": f"#{sans_rank}" if sans_rank else "not ranked",
        "nist_800_53": (frameworks.get("nist_800_53", []) or [])[:3],
        "pci_dss": (frameworks.get("pci_dss", []) or [])[:3],
        "owasp_wstg": (frameworks.get("owasp_wstg", []) or [])[:3],
        "iso_27001": (frameworks.get("iso_27001", []) or [])[:3],
    }
    fewshot = _build_fewshot_block(finding, cve_ids, cwe_id_list)
    if fewshot:
        payload["style_examples"] = fewshot
    return sanitize_value_for_egress(payload)


def _call_openrouter_batch(batch_payload: list[dict], cfg: dict) -> dict | None:
    messages = [
        {"role": "system", "content": LOOKUP_BATCH_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": LOOKUP_BATCH_USER_TEMPLATE.format(
                findings_json=json.dumps(batch_payload, ensure_ascii=False)
            ),
        },
    ]
    batch_json = json.dumps(batch_payload, ensure_ascii=False)
    raw = _call_openrouter(
        messages,
        cfg,
        task_type="lookup_critical",
        log_label="cloud_lookup_batch",
        request_original=batch_json,
    )
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}")
        if start == -1 or end <= start:
            return None
        try:
            parsed = json.loads(raw[start : end + 1])
        except json.JSONDecodeError:
            return None
    return parsed if isinstance(parsed, dict) else None


def _apply_cloud_result(
    finding: dict, cloud_entry: dict, deterministic_refs: list[dict]
) -> None:
    for key in (
        "control_objective",
        "control_name",
        "audit_requirement",
        "business_impact",
    ):
        val = cloud_entry.get(key)
        if val:
            finding[key] = val
    rec = cloud_entry.get("recommendation")
    if isinstance(rec, dict):
        finding["recommendation"] = {
            "primary": rec.get("primary", ""),
            "secondary": rec.get("secondary", ""),
            "defensive": rec.get("defensive", ""),
        }
        finding["remediation"] = _recommendation_to_remediation(
            finding["recommendation"]
        )
    cloud_refs = cloud_entry.get("reference") or []
    finding["reference"] = _merge_refs(cloud_refs, deterministic_refs)


def _apply_deterministic_fallback(
    finding: dict, source: dict, deterministic_refs: list[dict]
) -> None:
    rec_existing = finding.get("recommendation")
    if not (isinstance(rec_existing, dict) and rec_existing.get("primary")):
        legacy = source.get("remediation") or source.get("recommendation") or ""
        legacy_str = legacy if isinstance(legacy, str) else ""
        finding["recommendation"] = {
            "primary": legacy_str,
            "secondary": "",
            "defensive": "",
        }
    finding["remediation"] = _recommendation_to_remediation(
        finding.get("recommendation")
    )
    if not isinstance(finding.get("reference"), list):
        finding["reference"] = _merge_refs([], deterministic_refs)


def lookup_report(data: dict, cloud_cfg: dict, on_progress=None) -> dict:
    """Enrich all findings. Batched cloud calls (≤BATCH_SIZE per call).

    Pipeline per finding:
      1. rec_db lookup (skip LLM if cached)
      2. CVE/CWE/EPSS/CAPEC/framework lookup
      3. Deterministic baseline
      4. Batched cloud LLM with full context
      5. Store results to rec_db
    Idempotent: skips already-resolved findings.
    """
    findings = data.get("findings") or []
    total = len(findings)
    resolved_list: list[dict] = []
    pending: list[tuple[int, str, dict, list[dict], list[dict], list[str], str]] = []

    # Collect all CVE IDs for batch EPSS prefetch
    all_cve_ids: list[str] = []

    # First pass: deterministic + rec_db check + prep
    for idx, f in enumerate(findings):
        if _already_resolved(f):
            resolved_list.append(dict(f))
            continue

        resolved = dict(f)
        cve_data = _lookup_cves(f)
        cwe_ids = _collect_cwe_ids(f, cve_data)
        cwe_data_items = [fetch_cwe(cid) for cid in cwe_ids]
        cwe_data_items = [c for c in cwe_data_items if c]

        if cwe_data_items:
            primary_cwe = cwe_data_items[0]
            resolved.setdefault(
                "control_objective", primary_cwe.get("control_objective", "")
            )
            resolved.setdefault("control_name", primary_cwe.get("control_name", ""))
            if cwe_ids:
                resolved["cwe"] = ", ".join(cwe_ids)
        if cve_data:
            first_cve = cve_data[0]
            if first_cve.get("cvss") is not None:
                resolved["cvss"] = str(first_cve["cvss"])
            if first_cve.get("severity"):
                resolved.setdefault("severity", first_cve["severity"].title())
            if first_cve.get("description") and str(resolved.get("description") or "").strip().lower() in _PLACEHOLDER_TEXT:
                resolved["description"] = first_cve["description"]

        det_refs = _build_deterministic_refs(cve_data, cwe_data_items)

        # Check rec_db — skip LLM if cached
        _f_cves = [c.get("id", "") for c in cve_data if c.get("id")]
        _f_ctx = str(f.get("description", "") or "")
        cached = rec_db.lookup(
            cwe_ids,
            f.get("severity", ""),
            f.get("name", ""),
            cves=_f_cves,
            context=_f_ctx,
        )
        if cached:
            for key in (
                "control_objective",
                "control_name",
                "audit_requirement",
                "business_impact",
            ):
                if cached.get(key):
                    resolved[key] = cached[key]
            if isinstance(cached.get("recommendation"), dict):
                resolved["recommendation"] = cached["recommendation"]
                resolved["remediation"] = _recommendation_to_remediation(
                    cached["recommendation"]
                )
            resolved["reference"] = _merge_refs([], det_refs)
            resolved_list.append(resolved)
            continue

        for c in cve_data:
            cid = c.get("id", "")
            if cid and cid not in all_cve_ids:
                all_cve_ids.append(cid)

        resolved_list.append(resolved)
        key = f"f{idx}"
        pending.append(
            (
                idx,
                key,
                resolved,
                cve_data,
                cwe_data_items,
                cwe_ids,
                _short_progress_label(resolved),
            )
        )

    if not pending or not cloud_cfg.get("enabled"):
        for idx, key, resolved, cve_data, cwe_data_items, cwe_ids, _label in pending:
            det_refs = _build_deterministic_refs(cve_data, cwe_data_items)
            _apply_deterministic_fallback(resolved, findings[idx], det_refs)
        if cloud_cfg.get("enabled"):
            _emit_progress(
                on_progress,
                1,
                1,
                "Cloud lookup skipped — all findings were resolved locally.",
                {"phase": "cloud_lookup", "active_label": "", "active_items": []},
            )
        out = dict(data)
        out["findings"] = resolved_list
        return out

    # Batch EPSS prefetch for all pending CVEs
    epss_map = fetch_epss_batch(all_cve_ids) if all_cve_ids else {}
    cloud_total = len(pending)
    batch_size = max(1, int(cloud_cfg.get("batch_size") or BATCH_SIZE))
    processed_count = 0
    had_batch_failure = False
    prepared_batches: list[
        tuple[
            list[dict],
            list[
                tuple[
                    int,
                    str,
                    dict,
                    list[dict],
                    list[dict],
                    list[str],
                    str,
                    list[dict],
                    dict,
                    dict,
                ]
            ],
            list[str],
        ]
    ] = []

    for batch_start in range(0, len(pending), batch_size):
        batch = pending[batch_start : batch_start + batch_size]
        active_items = [label for *_meta, label in batch]
        batch_payload = []
        batch_meta: list[
            tuple[
                int,
                str,
                dict,
                list[dict],
                list[dict],
                list[str],
                str,
                list[dict],
                dict,
                dict,
            ]
        ] = []
        for idx, key, resolved, cve_data, cwe_data_items, cwe_ids, label in batch:
            capec_patterns = fetch_capec_for_cwes(cwe_ids)
            frameworks = get_merged_frameworks(cwe_ids)
            payload, restore_map = _prepare_batch_payload(
                resolved,
                key,
                cve_data,
                cwe_data_items,
                epss_map,
                capec_patterns,
                frameworks,
            )
            batch_payload.append(payload)
            batch_meta.append(
                (
                    idx,
                    key,
                    resolved,
                    cve_data,
                    cwe_data_items,
                    cwe_ids,
                    label,
                    capec_patterns,
                    frameworks,
                    restore_map,
                )
            )
        prepared_batches.append((batch_payload, batch_meta, active_items))

    for batch_payload, _batch_meta, _active_items in prepared_batches:
        messages = [
            {"role": "system", "content": LOOKUP_BATCH_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": LOOKUP_BATCH_USER_TEMPLATE.format(
                    findings_json=json.dumps(batch_payload, ensure_ascii=False)
                ),
            },
        ]
        try:
            assert_safe_for_egress(
                {
                    "model": cloud_cfg.get("model", ""),
                    "messages": messages,
                }
            )
        except EgressViolation as exc:
            raise_client_data_egress_error(
                "structured lookup enrichment preflight",
                "OpenRouter",
                f"Sanitization could not safely remove all client data ({exc}).",
            )

    # Batched cloud lookup
    for batch_payload, batch_meta, active_items in prepared_batches:
        active_index = min(cloud_total, processed_count + 1)
        _emit_progress(
            on_progress,
            active_index,
            cloud_total,
            _build_cloud_lookup_message(active_index, cloud_total, active_items),
            {
                "phase": "cloud_lookup",
                "active_label": active_items[0] if len(active_items) == 1 else "",
                "active_items": active_items,
                "completed": processed_count,
                "batch_size": len(active_items),
            },
        )

        try:
            result = _call_openrouter_batch(batch_payload, cloud_cfg)
        except ClientDataInternetEgressError:
            raise
        except (EgressViolation, httpx.HTTPError, RuntimeError, KeyError) as e:
            had_batch_failure = True
            # Surface cloud batch errors via on_progress when available so
            # callers (adapter -> server -> UI) can show an explanatory message
            # instead of silently continuing.
            _emit_progress(
                on_progress,
                active_index,
                cloud_total,
                f"Cloud batch lookup failed: {e}",
                {
                    "phase": "cloud_lookup",
                    "active_label": active_items[0] if len(active_items) == 1 else "",
                    "active_items": active_items,
                    "completed": processed_count,
                    "batch_size": len(active_items),
                },
            )
            result = None

        results_by_key: dict[str, dict] = {}
        if result and isinstance(result.get("results"), list):
            for item in result["results"]:
                if isinstance(item, dict) and item.get("key"):
                    results_by_key[item["key"]] = item

        for (
            idx,
            key,
            resolved,
            cve_data,
            cwe_data_items,
            cwe_ids,
            _label,
            capec_patterns,
            frameworks,
            restore_map,
        ) in batch_meta:
            det_refs = _build_deterministic_refs(cve_data, cwe_data_items)
            cloud_entry = results_by_key.get(key)
            if cloud_entry:
                cloud_entry = restore_placeholders(cloud_entry, restore_map)
                _apply_cloud_result(resolved, cloud_entry, det_refs)
                qs = _quality_score(cloud_entry)
                _s_cves = [c.get("id", "") for c in cve_data if c.get("id")]
                _s_ctx = str(findings[idx].get("description", "") or "")
                rec_db.store(
                    cwe_ids,
                    findings[idx].get("severity", ""),
                    findings[idx].get("name", ""),
                    cloud_entry,
                    qs,
                    cves=_s_cves,
                    context=_s_ctx,
                )
            else:
                _apply_deterministic_fallback(resolved, findings[idx], det_refs)
        processed_count += len(batch)

    if not had_batch_failure:
        _emit_progress(
            on_progress,
            cloud_total,
            cloud_total,
            f"Cloud lookup complete — {cloud_total}/{cloud_total} eligible findings processed ({total} total findings).",
            {"phase": "cloud_lookup", "active_label": "", "active_items": []},
        )

    out = dict(data)
    out["findings"] = resolved_list
    out["_lookup_stats"] = {
        "total_findings": total,
        "cloud_eligible_findings": cloud_total,
        "resolved_without_cloud": total - cloud_total,
    }
    return out


def enrich_report(data: dict, cloud_cfg: dict, on_progress=None) -> dict:
    """Backward-compatible alias for older call sites."""
    return lookup_report(data, cloud_cfg, on_progress=on_progress)
