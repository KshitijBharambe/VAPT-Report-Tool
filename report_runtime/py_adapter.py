import base64
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import generate_report as gr
from report_tool.llm import ModelFetchError, fetch_models_for_provider

CONFIG_PATH = ROOT_DIR / "config.json"
OUTPUT_DIR = ROOT_DIR / "outputs" / "runtime_reports"


def _resolve_log_dir() -> Path:
    cfg = gr.load_config(str(CONFIG_PATH))
    raw_log_dir = str(((cfg or {}).get("paths") or {}).get("log_dir") or "logs").strip()
    candidate = Path(raw_log_dir)
    if not candidate.is_absolute():
        candidate = ROOT_DIR / candidate
    return candidate.resolve()


def _list_run_logs() -> list[Path]:
    log_dir = _resolve_log_dir()
    if not log_dir.exists():
        return []
    return sorted(log_dir.glob("*_run_log.json"), key=lambda item: item.stat().st_mtime)


def _count_llm_interactions(run_log_path: str | Path | None) -> int:
    if not run_log_path:
        return 0
    try:
        payload = json.loads(Path(run_log_path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return 0
    events = payload.get("events") if isinstance(payload, dict) else []
    if not isinstance(events, list):
        return 0
    return sum(1 for event in events if event.get("type") == "llm_interaction")


def _build_runtime_config_path(payload: dict) -> str:
    cfg = gr.load_config(str(CONFIG_PATH))
    llm = cfg.setdefault("llm", {})

    provider = str(payload.get("provider") or "").strip().lower()
    model = str(payload.get("model") or "").strip()
    base_url = str(payload.get("base_url") or "").strip()

    if provider in {"local", "openrouter"}:
        llm["provider"] = provider
    if model:
        llm["model"] = model
        # If a runtime model override is provided explicitly by the caller,
        # remove any default `task_models` coming from config.json so that
        # the runtime `model` takes precedence for cloud detail lookup.
        if "task_models" in llm:
            llm.pop("task_models", None)
    if base_url:
        llm["base_url"] = base_url

    # Validate provider/base_url coherence — fail fast on mismatch.
    effective_provider = llm.get("provider", "local")
    effective_base_url = llm.get("base_url", "")
    if effective_provider == "local" and "openrouter.ai" in effective_base_url:
        raise ValueError(
            f"Provider is 'local' but base_url points to OpenRouter ({effective_base_url}). "
            "Send base_url for your local model server, or set provider to 'openrouter'."
        )
    if (
        effective_provider == "openrouter"
        and effective_base_url
        and "openrouter.ai" not in effective_base_url
    ):
        raise ValueError(
            f"Provider is 'openrouter' but base_url points elsewhere ({effective_base_url}). "
            "Remove base_url to use OpenRouter, or set provider to 'local'."
        )

    with NamedTemporaryFile(
        prefix="runtime_cfg_",
        suffix=".json",
        mode="w",
        encoding="utf-8",
        delete=False,
    ) as tmp:
        json.dump(cfg, tmp, indent=2)
        return tmp.name


def _read_stdin_json() -> dict:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    return json.loads(raw)


def _write_temp_upload(filename: str, content_b64: str) -> Path:
    suffix = Path(filename).suffix or ".txt"
    allowed_suffixes = {".txt", ".csv", ".xlsx", ".xls"}
    if suffix.lower() not in allowed_suffixes:
        raise ValueError(
            f"Unsupported upload file type: {suffix}. Allowed: {sorted(allowed_suffixes)}"
        )
    with NamedTemporaryFile(
        prefix="runtime_upload_", suffix=suffix, delete=False
    ) as tmp:
        tmp.write(base64.b64decode(content_b64))
        return Path(tmp.name)


def _default_output_path(client_name: str | None = None) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    safe_client = re.sub(r"[^\w\-]", "_", (client_name or "client").strip())
    if not safe_client:
        safe_client = "client"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = OUTPUT_DIR.resolve()
    out_path = (output_dir / f"{safe_client}_report_{stamp}.docx").resolve()
    if not str(out_path).startswith(str(output_dir) + os.sep):
        raise ValueError("Generated output path escaped the runtime output directory.")
    return out_path


def _resolve_template_path(template_path: str) -> Path:
    candidate = Path(template_path)
    if not candidate.is_absolute():
        candidate = ROOT_DIR / candidate
    resolved = candidate.resolve()
    root_dir = ROOT_DIR.resolve()
    if resolved.suffix.lower() != ".docx":
        raise ValueError("template_path must point to a .docx template file.")
    if not str(resolved).startswith(str(root_dir) + os.sep):
        raise ValueError("template_path must stay within the project directory.")
    if not resolved.is_file():
        raise ValueError(f"Template file not found: {resolved}")
    return resolved


def _resolve_generate_template_path(template_path: str) -> Path:
    requested_template = str(template_path or "").strip()
    if not requested_template:
        raise ValueError(
            "No report template found. Upload a .docx base template first."
        )
    return _resolve_template_path(requested_template)


def _run_analyze(payload: dict) -> dict:
    filename = str(payload.get("filename") or "").strip()
    content_b64 = str(payload.get("file_content_base64") or "").strip()
    client_context = str(payload.get("client_context") or payload.get("context") or "")
    api_key = str(payload.get("api_key") or "")

    if not filename or not content_b64:
        return {"ok": False, "error": "filename and file_content_base64 are required"}

    upload_path = _write_temp_upload(filename, content_b64)
    runtime_config_path = ""

    def _emit_progress(
        stage: str,
        current: int,
        total: int,
        message: str,
        detail: dict | None = None,
    ) -> None:
        try:
            progress = {
                "stage": stage,
                "current": int(current),
                "total": int(total),
                "message": str(message),
            }
            if isinstance(detail, dict) and detail:
                progress["detail"] = detail
            sys.stderr.write("__PROGRESS__" + json.dumps(progress) + "\n")
            sys.stderr.flush()
        except Exception:
            # Progress reporting must never break analysis execution.
            pass

    try:
        runtime_config_path = _build_runtime_config_path(payload)
        run_logs_before = {str(path) for path in _list_run_logs()}
        data, raw_texts, false_positives = gr.generate_per_vuln(
            str(upload_path),
            config_path=runtime_config_path,
            client_context=client_context,
            progress_callback=_emit_progress,
            api_key=api_key,
        )
    finally:
        if runtime_config_path:
            Path(runtime_config_path).unlink(missing_ok=True)
        upload_path.unlink(missing_ok=True)

    run_logs_after = _list_run_logs()
    new_run_logs = [path for path in run_logs_after if str(path) not in run_logs_before]
    run_log_path = new_run_logs[-1] if new_run_logs else (run_logs_after[-1] if run_logs_after else None)

    # Attach source filename to data so history can record it
    if isinstance(data, dict):
        data["_source_file"] = Path(upload_path).name
        data["_input_name"] = filename
        data["_run_log_path"] = str(run_log_path) if run_log_path else ""
        data["_llm_interaction_count"] = _count_llm_interactions(run_log_path)
        data["false_positives"] = false_positives or []

    return {
        "ok": True,
        "analysis_id": datetime.now().strftime("a%Y%m%d%H%M%S%f"),
        "data": data,
        "raw_count": len(raw_texts or []),
        "raw_texts": raw_texts or [],
        "false_positives": false_positives or [],
        "llm_interaction_count": (
            data.get("_llm_interaction_count", 0) if isinstance(data, dict) else 0
        ),
        "uploaded_path": str(upload_path),
        "run_log_path": str(run_log_path) if run_log_path else "",
    }


def _run_generate(payload: dict) -> dict:
    data = payload.get("analysis_data")
    if not isinstance(data, dict):
        return {"ok": False, "error": "analysis_data is required"}

    template_path = str(payload.get("template_path") or "").strip()
    include_summary_table = bool(payload.get("include_summary_table", True))
    template_path = str(_resolve_generate_template_path(template_path))

    out_path = _default_output_path(data.get("client_name"))

    gr.render_report(
        data,
        template_path=template_path,
        output_path=str(out_path),
        include_summary_table=include_summary_table,
    )

    docx_bytes = out_path.read_bytes()
    return {
        "ok": True,
        "file_name": out_path.name,
        "output_path": str(out_path),
        "docx_base64": base64.b64encode(docx_bytes).decode("ascii"),
    }


def _run_models(payload: dict) -> dict:
    provider = str(payload.get("provider") or "local").strip().lower()
    base_url = str(payload.get("base_url") or "").strip()
    api_key = str(payload.get("api_key") or "")
    try:
        models = fetch_models_for_provider(provider, base_url, api_key)
    except ModelFetchError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "models": models}


def main() -> int:
    try:
        payload = _read_stdin_json()
        action = str(payload.get("action") or "").strip().lower()

        if action == "analyze":
            result = _run_analyze(payload)
        elif action == "generate":
            result = _run_generate(payload)
        elif action == "models":
            result = _run_models(payload)
        elif action in {"health", "ping"}:
            result = {"ok": True, "status": "ok"}
        else:
            result = {"ok": False, "error": f"Unsupported action: {action}"}

        sys.stdout.write(json.dumps(result))
        return 0 if result.get("ok") else 1
    except Exception as exc:  # pragma: no cover - integration boundary
        sys.stdout.write(json.dumps({"ok": False, "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
