"""Helpers for writing a single structured log per report run."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from threading import Lock

_RUN_LOG_SUFFIX = "_run_log.json"
_RUN_LOG_LOCK = Lock()


def _json_safe(value):
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, set):
        return [_json_safe(item) for item in sorted(value, key=lambda item: str(item))]
    return value


def ensure_run_log(config: dict, *, pipeline: str = "") -> str:
    """Create a run-scoped log file once and return its path."""
    existing = str((config or {}).get("_run_log_path") or "").strip()
    if existing:
        return existing

    cfg = config if isinstance(config, dict) else {}
    paths_cfg = cfg.setdefault("paths", {})
    log_dir = Path(paths_cfg.get("log_dir") or "logs")
    log_dir.mkdir(parents=True, exist_ok=True)

    path = log_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}{_RUN_LOG_SUFFIX}"
    payload = {
        "log_version": 1,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "pipeline": pipeline or str(cfg.get("_pipeline_name") or ""),
        "provider": str(((cfg.get("llm") or {}).get("provider") or "")),
        "model": str(((cfg.get("llm") or {}).get("model") or "")),
        "events": [],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    cfg["_run_log_path"] = str(path)
    return str(path)


def append_run_log_event(config: dict, event_type: str, data: dict) -> str:
    """Append a structured event to the active run log."""
    path = Path(ensure_run_log(config))
    event = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "type": str(event_type),
        "data": _json_safe(data or {}),
    }

    with _RUN_LOG_LOCK:
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload.setdefault("events", []).append(event)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    return str(path)


def build_llm_event(
    *,
    log_label: str,
    task_type: str | None,
    attempt: int,
    config: dict,
    request_payload: dict,
    user_content_original: str,
    user_content_sent: str,
    response_received_raw: str,
    response_restored: str,
) -> dict:
    llm_cfg = (config or {}).get("llm", {})
    return {
        "label": log_label,
        "task_type": task_type or "",
        "attempt": int(attempt),
        "provider": str(llm_cfg.get("provider") or ""),
        "model": str(llm_cfg.get("model") or ""),
        "request_payload": request_payload,
        "user_content_original": user_content_original,
        "user_content_sent": user_content_sent,
        "response_received_raw": response_received_raw,
        "response_restored": response_restored,
    }
