import json
import sys
import time

from report_core.constants import SYSTEM_PROMPT
from report_core.json_schema import safe_parse_json
from report_core.privacy import (
    EgressViolation,
    assert_safe_for_egress,
    prepare_text_for_cloud_egress,
    raise_client_data_egress_error,
    restore_placeholders,
)
from report_tool.run_logging import append_run_log_event, build_llm_event


class ModelFetchError(RuntimeError):
    """Raised when the model catalogue cannot be reached."""


def fetch_lm_studio_models(base_url: str, api_key: str = "") -> list:
    """Query a local OpenAI-compatible /v1/models endpoint and return model IDs."""
    import httpx

    if not base_url:
        raise ModelFetchError("Local base URL is empty.")
    url = base_url.rstrip("/") + "/models"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(url, headers=headers)
            resp.raise_for_status()
            return [m["id"] for m in resp.json().get("data", [])]
    except httpx.HTTPStatusError as e:
        body = ""
        try:
            body = e.response.text.strip()
        except Exception:
            pass
        raise ModelFetchError(
            f"Local provider HTTP {e.response.status_code} from {url}"
            + (f": {body}" if body else "")
        ) from e
    except httpx.RequestError as e:
        raise ModelFetchError(f"Local provider unreachable at {url}: {e}") from e


def fetch_openrouter_models(api_key: str) -> list:
    """Query OpenRouter /api/v1/models and return text-model IDs."""
    import httpx

    if not api_key:
        raise ModelFetchError("OpenRouter API key required to list models.")
    url = "https://openrouter.ai/api/v1/models"
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(url, headers=headers)
            resp.raise_for_status()
            models = resp.json().get("data", [])
    except httpx.HTTPStatusError as e:
        body = ""
        try:
            body = e.response.text.strip()
        except Exception:
            pass
        raise ModelFetchError(
            f"OpenRouter HTTP {e.response.status_code}" + (f": {body}" if body else "")
        ) from e
    except httpx.RequestError as e:
        raise ModelFetchError(f"OpenRouter unreachable: {e}") from e

    text_models = [
        m["id"]
        for m in models
        if "text" in str(m.get("architecture", {}).get("modality", "")).lower()
        or m.get("id", "").startswith(
            (
                "openai/",
                "anthropic/",
                "google/",
                "meta-llama/",
                "deepseek/",
                "qwen/",
                "mistralai/",
                "cohere/",
            )
        )
    ]
    return sorted(text_models)


def fetch_models_for_provider(provider: str, base_url: str, api_key: str = "") -> list:
    """Fetch model IDs for configured provider; raises ModelFetchError on failure."""
    normalized = (provider or "local").strip().lower()
    if normalized == "openrouter":
        return fetch_openrouter_models(api_key)
    target_base_url = (base_url or "").strip()
    if not target_base_url:
        raise ModelFetchError("Local base URL missing.")
    return fetch_lm_studio_models(target_base_url, api_key)


class CancelledError(Exception):
    """Raised when the user cancels an in-flight LLM request."""


class TokenBudgetExceeded(RuntimeError):
    """Raised when cumulative token usage exceeds the per-report budget."""


# ── Per-report token budget tracking ────────────────────────────────────────
_token_budget_used: int = 0
_token_budget_limit: int = 0  # 0 = unlimited


def reset_token_budget(limit: int = 0) -> None:
    """Reset the budget counter. Call at the start of each report generation."""
    global _token_budget_used, _token_budget_limit
    _token_budget_used = 0
    _token_budget_limit = max(int(limit), 0)


def get_token_budget_used() -> int:
    return _token_budget_used


def _estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 chars per token (conservative)."""
    return max(len(text) // 4, 1)


def _track_tokens(text: str) -> None:
    """Add estimated tokens to running total; raise if budget exceeded."""
    global _token_budget_used
    estimated = _estimate_tokens(text)
    _token_budget_used += estimated
    if _token_budget_limit > 0 and _token_budget_used > _token_budget_limit:
        raise TokenBudgetExceeded(
            f"Token budget exceeded: {_token_budget_used:,} estimated tokens used "
            f"(limit: {_token_budget_limit:,}). Aborting to prevent runaway spend."
        )


def _extract_response_error_message(response) -> str:
    if response is None:
        return ""

    try:
        data = response.json()
        if isinstance(data, dict):
            err = data.get("error")
            if isinstance(err, dict):
                for key in ("message", "detail", "code"):
                    value = err.get(key)
                    if isinstance(value, str) and value.strip():
                        return value.strip()
            if isinstance(err, str) and err.strip():
                return err.strip()
    except Exception:
        # Fall through to a safe attempt at reading plain text from the
        # response body. Accessing `response.text` can itself raise if the
        # response is a streaming one and hasn't been consumed; guard it.
        try:
            text = str(getattr(response, "text", "") or "").strip()
        except Exception:
            text = ""
        return text

    # If JSON parsing succeeded but didn't contain an error string,
    # still try to return any available textual content safely.
    try:
        text = str(getattr(response, "text", "") or "").strip()
    except Exception:
        text = ""
    return text


def _format_provider_http_error(provider: str, error) -> str:
    provider_name = "OpenRouter" if provider == "openrouter" else "LLM provider"

    try:
        import httpx
    except ImportError:  # pragma: no cover - runtime dependency always present in tests
        httpx = None

    if httpx is not None and isinstance(error, httpx.HTTPStatusError):
        response = error.response
        status_code = getattr(response, "status_code", "?")
        retry_after = ""
        if response is not None:
            # Read/consume streaming response content if possible so downstream
            # accessors (response.json(), response.text) do not raise the
            # "Attempted to access streaming response content" error.
            try:
                read_fn = getattr(response, "read", None)
                if callable(read_fn):
                    try:
                        read_fn()
                    except Exception:
                        # If reading fails, fall back to best-effort extraction below.
                        pass
            except Exception:
                pass
            retry_after = str(response.headers.get("retry-after") or "").strip()

        # Attempt to extract a useful error detail, but fall back gracefully
        # if the response body is still unavailable or parsing fails.
        try:
            detail = _extract_response_error_message(response)
        except Exception:
            detail = ""

        message = f"{provider_name} HTTP {status_code}"
        if detail:
            message += f": {detail}"
        if retry_after:
            message += f". Retry-After: {retry_after} seconds."
        return message

    if httpx is not None and isinstance(error, httpx.RequestError):
        return f"{provider_name} request failed: {error}"

    return str(error)


def resolve_task_model(config: dict, task_type: str | None) -> str:
    """Return the selected model id for a task, or an empty string if none is set.

    config["llm"]["task_models"] is an optional {task_type: model_id} map.
    Unknown task_type falls back to the explicitly selected llm.model.
    """
    llm_cfg = config.get("llm", {})
    task_models = llm_cfg.get("task_models") or {}
    if not isinstance(task_models, dict):
        task_models = {}

    if task_type:
        task_model = (task_models.get(task_type) or "").strip()
        if task_model:
            return task_model

    return (llm_cfg.get("model") or "").strip()


def probe_local_endpoint(base_url: str, timeout: float = 5.0) -> None:
    """Check that the local model server is reachable before starting a pipeline.

    Makes a lightweight HEAD/GET request to the base URL.  Raises ``RuntimeError``
    with a descriptive message when the endpoint is unreachable so the caller can
    fail fast instead of discovering connectivity problems mid-pipeline.
    """
    try:
        import httpx
    except ImportError:
        return  # can't probe without httpx; skip silently

    probe_url = base_url.rstrip("/")
    # Prefer /models (OpenAI-compatible list) as the health-check endpoint.
    for suffix in ("/models", ""):
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(probe_url + suffix)
            # Any HTTP response (even 401/404) means the server is up.
            return
        except httpx.ConnectError:
            pass  # try next suffix
        except Exception:
            pass  # try next suffix

    raise RuntimeError(
        f"Cannot reach local model server at {base_url}. "
        "Make sure LM Studio (or your local server) is running and listening on the configured port."
    )


def _build_payload(
    scan_text: str,
    config: dict,
    system_prompt: str = None,
    user_content: str = None,
    task_type: str | None = None,
) -> dict:
    llm_cfg = config["llm"]
    safe_max_tokens = min(int(llm_cfg.get("max_tokens", 8192)), 32768)

    if system_prompt is None:
        system_prompt = SYSTEM_PROMPT
    if user_content is None:
        user_content = (
            "Analyse the following VAPT scan data and return the structured JSON report.\n"
            "IMPORTANT: Copy severity, observation, and remediation_status DIRECTLY from the scan — do not override them.\n\n"
            + scan_text
        )

    model_id = resolve_task_model(config, task_type)
    if not model_id:
        raise ValueError(
            f"No model selected for task {task_type or 'default'}; choose a model before running analysis."
        )

    # Build messages — add Anthropic cache_control on system prompt when applicable
    system_msg = {"role": "system", "content": system_prompt}
    if (
        llm_cfg.get("provider") == "openrouter"
        and isinstance(model_id, str)
        and model_id.startswith("anthropic/")
    ):
        system_msg["cache_control"] = {"type": "ephemeral"}

    payload = {
        "model": model_id,
        "temperature": llm_cfg.get("temperature", 0.1),
        "max_tokens": safe_max_tokens,
        "stream": True,
        "messages": [
            system_msg,
            {"role": "user", "content": user_content},
        ],
    }

    # Only request JSON mode for providers/models that support it natively.
    # Local providers (LM Studio, Ollama, etc.) often reject or ignore this field
    # when the loaded model has no built-in JSON grammar enforcement.
    _provider = llm_cfg.get("provider", "local")
    if _provider in ("openrouter", "openai") or llm_cfg.get("json_mode", False):
        payload["response_format"] = {"type": "json_object"}

    for key in ("top_p", "frequency_penalty", "presence_penalty", "seed", "stop"):
        if key in llm_cfg and llm_cfg[key] is not None:
            payload[key] = llm_cfg[key]

    return payload


def _validate_provider_base_url(llm_cfg: dict) -> None:
    """Fail fast if provider and base_url are incoherent."""
    provider = llm_cfg.get("provider", "local")
    base_url = llm_cfg.get("base_url", "")
    if provider == "local" and "openrouter.ai" in base_url:
        raise RuntimeError(
            f"Provider is 'local' but base_url points to OpenRouter ({base_url}). "
            "Fix config or set provider to 'openrouter'."
        )
    if provider == "openrouter" and base_url and "openrouter.ai" not in base_url:
        raise RuntimeError(
            f"Provider is 'openrouter' but base_url points elsewhere ({base_url}). "
            "Fix config or set provider to 'local'."
        )


def _classify_llm_error(error) -> str:
    """Classify an LLM error to decide retry strategy.

    Returns one of:
      'no_retry'  – auth, billing, length-exceeded; retrying wastes money
      'retry'     – transient 5xx, rate-limit, network; worth retrying
    """
    try:
        import httpx
    except ImportError:
        httpx = None

    err_str = str(error).lower()

    # HTTP status-based classification
    if httpx is not None and isinstance(error, httpx.HTTPStatusError):
        code = error.response.status_code
        if code in (401, 403):
            return "no_retry"
        if code == 402:  # billing / payment required
            return "no_retry"
        if code in (429, 500, 502, 503, 504, 520, 524):
            return "retry"

    # String heuristics for wrapped errors
    if any(s in err_str for s in ("401", "403", "unauthorized", "forbidden")):
        return "no_retry"
    if any(
        s in err_str
        for s in (
            "max_tokens",
            "context_length",
            "length exceeded",
            "maximum context length",
            "too many tokens",
        )
    ):
        return "no_retry"
    if any(s in err_str for s in ("402", "payment", "billing", "insufficient_quota")):
        return "no_retry"

    return "retry"


def _retry_backoff(attempt: int) -> float:
    """Exponential backoff: 3s, 6s, 12s, ..."""
    return min(3 * (2 ** (attempt - 1)), 60)


def _restore_llm_output(raw_text: str, restore_map: dict) -> str:
    if not restore_map:
        return raw_text
    restored = restore_placeholders(safe_parse_json(raw_text), restore_map)
    return json.dumps(restored, ensure_ascii=False)


def call_llm(scan_text: str, config: dict, cancel_event=None) -> str:
    """Call the LLM via httpx streaming (cancellable). Falls back to openai SDK."""
    _validate_provider_base_url(config.get("llm", {}))
    user_content, restore_map = prepare_text_for_cloud_egress(
        "Analyse the following VAPT scan data and return the structured JSON report.\n"
        "IMPORTANT: Copy severity, observation, and remediation_status DIRECTLY from the scan — do not override them.\n\n"
        + scan_text,
        config,
        "scan analysis",
    )
    try:
        import httpx
    except ImportError:
        return _call_llm_openai(scan_text, config)

    llm_cfg = config["llm"]
    provider = llm_cfg.get("provider", "local")
    max_retries = llm_cfg.get("max_retries", 3)
    base_url = llm_cfg["base_url"].rstrip("/")
    url = f"{base_url}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if llm_cfg.get("api_key"):
        headers["Authorization"] = f"Bearer {llm_cfg['api_key']}"
    if llm_cfg.get("provider") == "openrouter":
        headers["X-Title"] = "VAPT Report Generator"

    payload = _build_payload("", config, user_content=user_content)
    if provider != "local":
        try:
            assert_safe_for_egress(payload)
        except EgressViolation as exc:
            raise_client_data_egress_error(
                "scan analysis",
                provider,
                f"Sanitization could not safely remove all client data ({exc}).",
            )

    last_error = None
    for attempt in range(1, max_retries + 1):
        if cancel_event and cancel_event.is_set():
            raise CancelledError("Cancelled before attempt started.")
        try:
            chunks = []
            with httpx.Client(timeout=httpx.Timeout(10.0, read=300.0)) as client:
                with client.stream("POST", url, json=payload, headers=headers) as resp:
                    resp.raise_for_status()
                    for line in resp.iter_lines():
                        if cancel_event and cancel_event.is_set():
                            raise CancelledError("Cancelled by user during streaming.")
                        if not line or not line.startswith("data:"):
                            continue
                        data_str = line[len("data:") :].strip()
                        if data_str == "[DONE]":
                            break
                        try:
                            chunk = json.loads(data_str)
                            delta = chunk["choices"][0].get("delta", {})
                            if "content" in delta and delta["content"]:
                                chunks.append(delta["content"])
                        except Exception:
                            continue

            raw_text = "".join(chunks)
            if not raw_text.strip():
                raise RuntimeError(
                    "Model returned an empty response. This usually means the model crashed "
                    "(OOM/segfault) in LM Studio. Try: restart LM Studio, use a smaller model, "
                    "or reduce max_tokens in config."
                )

            restored_text = _restore_llm_output(raw_text, restore_map)
            append_run_log_event(
                config,
                "llm_interaction",
                build_llm_event(
                    log_label="scan_analysis",
                    task_type="scan_analysis",
                    attempt=attempt,
                    config=config,
                    request_payload=payload,
                    user_content_original=(
                        "Analyse the following VAPT scan data and return the structured JSON report.\n"
                        "IMPORTANT: Copy severity, observation, and remediation_status DIRECTLY from the scan — do not override them.\n\n"
                        + scan_text
                    ),
                    user_content_sent=user_content,
                    response_received_raw=raw_text,
                    response_restored=restored_text,
                ),
            )
            safe_parse_json(raw_text)  # validate before returning
            _track_tokens(raw_text)
            return restored_text

        except CancelledError:
            raise
        except RuntimeError as e:
            if "empty response" in str(e):
                raise
            last_error = e
            append_run_log_event(
                config,
                "llm_error",
                {
                    "label": "scan_analysis",
                    "task_type": "scan_analysis",
                    "attempt": attempt,
                    "error": str(e),
                },
            )
            print(
                f"⚠️  LLM attempt {attempt}/{max_retries} failed: {e}", file=sys.stderr
            )
            if _classify_llm_error(e) == "no_retry":
                break
            if attempt < max_retries:
                time.sleep(_retry_backoff(attempt))
        except Exception as e:
            formatted_error = _format_provider_http_error(provider, e)
            last_error = RuntimeError(formatted_error)
            append_run_log_event(
                config,
                "llm_error",
                {
                    "label": "scan_analysis",
                    "task_type": "scan_analysis",
                    "attempt": attempt,
                    "error": formatted_error,
                },
            )
            print(
                f"⚠️  LLM attempt {attempt}/{max_retries} failed: {formatted_error}",
                file=sys.stderr,
            )
            if _classify_llm_error(e) == "no_retry":
                break
            if attempt < max_retries:
                time.sleep(_retry_backoff(attempt))

    raise RuntimeError(
        f"LLM call failed after {max_retries} attempts. Last error: {last_error}\n"
        f"Check LM Studio at {llm_cfg['base_url']} with model '{llm_cfg['model']}'."
    )


def _call_llm_openai(scan_text: str, config: dict) -> str:
    """Fallback: openai SDK."""
    import openai

    user_content, restore_map = prepare_text_for_cloud_egress(
        "Analyse the following VAPT scan data and return the structured JSON report.\n"
        "IMPORTANT: Copy severity, observation, and remediation_status DIRECTLY from the scan.\n\n"
        + scan_text,
        config,
        "scan analysis",
    )
    llm_cfg = config["llm"]
    safe_max_tokens = min(int(llm_cfg.get("max_tokens", 8192)), 32768)
    client = openai.OpenAI(
        base_url=llm_cfg["base_url"],
        api_key=llm_cfg.get("api_key") or "not-required-for-local",
    )
    create_kwargs = {
        "model": llm_cfg["model"],
        "temperature": llm_cfg.get("temperature", 0.1),
        "max_tokens": safe_max_tokens,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
    }
    response = client.chat.completions.create(**create_kwargs)
    raw_text = response.choices[0].message.content or ""
    restored_text = _restore_llm_output(raw_text, restore_map)
    append_run_log_event(
        config,
        "llm_interaction",
        build_llm_event(
            log_label="scan_analysis",
            task_type="scan_analysis",
            attempt=1,
            config=config,
            request_payload=create_kwargs,
            user_content_original=(
                "Analyse the following VAPT scan data and return the structured JSON report.\n"
                "IMPORTANT: Copy severity, observation, and remediation_status DIRECTLY from the scan.\n\n"
                + scan_text
            ),
            user_content_sent=user_content,
            response_received_raw=raw_text,
            response_restored=restored_text,
        ),
    )
    _track_tokens(raw_text)
    return restored_text


def _call_llm_generic(
    system_prompt: str,
    user_content: str,
    config: dict,
    cancel_event=None,
    log_label: str = "chunk",
    task_type: str | None = None,
) -> str:
    """Low-level LLM call with custom prompts. Used by chunked pipeline."""
    _validate_provider_base_url(config.get("llm", {}))
    action = task_type or "LLM enrichment"
    original_user_content = user_content
    sanitized_user_content, restore_map = prepare_text_for_cloud_egress(
        user_content,
        config,
        action,
    )
    try:
        import httpx
    except ImportError:
        import openai

        llm_cfg = config["llm"]
        client = openai.OpenAI(
            base_url=llm_cfg["base_url"], api_key=llm_cfg["api_key"] or "lm-studio"
        )
        provider = llm_cfg.get("provider", "local")
        create_kwargs = {
            "model": resolve_task_model(config, task_type),
            "temperature": llm_cfg.get("temperature", 0.1),
            "max_tokens": min(int(llm_cfg.get("max_tokens", 8192)), 32768),
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": sanitized_user_content},
            ],
        }
        # Only add response_format for providers that support it
        if provider in ("openrouter", "openai") or llm_cfg.get("json_mode", False):
            create_kwargs["response_format"] = {"type": "json_object"}
        response = client.chat.completions.create(**create_kwargs)
        result = response.choices[0].message.content or ""
        restored_text = _restore_llm_output(result, restore_map)
        append_run_log_event(
            config,
            "llm_interaction",
            build_llm_event(
                log_label=log_label,
                task_type=task_type,
                attempt=1,
                config=config,
                request_payload=create_kwargs,
                user_content_original=original_user_content,
                user_content_sent=sanitized_user_content,
                response_received_raw=result,
                response_restored=restored_text,
            ),
        )
        _track_tokens(result)
        return restored_text

    llm_cfg = config["llm"]
    provider = llm_cfg.get("provider", "local")
    max_retries = llm_cfg.get("max_retries", 3)
    base_url = llm_cfg["base_url"].rstrip("/")
    url = f"{base_url}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if llm_cfg.get("api_key"):
        headers["Authorization"] = f"Bearer {llm_cfg['api_key']}"
    if llm_cfg.get("provider") == "openrouter":
        headers["X-Title"] = "VAPT Report Generator"

    payload = _build_payload(
        "",
        config,
        system_prompt=system_prompt,
        user_content=sanitized_user_content,
        task_type=task_type,
    )
    if provider != "local":
        try:
            assert_safe_for_egress(payload)
        except EgressViolation as exc:
            raise_client_data_egress_error(
                action,
                provider,
                f"Sanitization could not safely remove all client data ({exc}).",
            )

    last_error = None
    for attempt in range(1, max_retries + 1):
        if cancel_event and cancel_event.is_set():
            raise CancelledError("Cancelled before attempt started.")
        try:
            chunks = []
            with httpx.Client(timeout=httpx.Timeout(10.0, read=300.0)) as client:
                with client.stream("POST", url, json=payload, headers=headers) as resp:
                    resp.raise_for_status()
                    for line in resp.iter_lines():
                        if cancel_event and cancel_event.is_set():
                            raise CancelledError("Cancelled by user during streaming.")
                        if not line or not line.startswith("data:"):
                            continue
                        data_str = line[len("data:") :].strip()
                        if data_str == "[DONE]":
                            break
                        try:
                            chunk = json.loads(data_str)
                            delta = chunk["choices"][0].get("delta", {})
                            if "content" in delta and delta["content"]:
                                chunks.append(delta["content"])
                        except Exception:
                            continue

            raw_text = "".join(chunks)
            if not raw_text.strip():
                raise RuntimeError(
                    "Model returned an empty response. Try restarting LM Studio "
                    "or using a smaller model."
                )

            restored_text = _restore_llm_output(raw_text, restore_map)
            append_run_log_event(
                config,
                "llm_interaction",
                build_llm_event(
                    log_label=log_label,
                    task_type=task_type,
                    attempt=attempt,
                    config=config,
                    request_payload=payload,
                    user_content_original=original_user_content,
                    user_content_sent=sanitized_user_content,
                    response_received_raw=raw_text,
                    response_restored=restored_text,
                ),
            )
            _track_tokens(raw_text)
            return restored_text

        except CancelledError:
            raise
        except RuntimeError as e:
            if "empty response" in str(e):
                raise
            last_error = e
            append_run_log_event(
                config,
                "llm_error",
                {
                    "label": log_label,
                    "task_type": task_type or "",
                    "attempt": attempt,
                    "error": str(e),
                },
            )
            print(
                f"⚠️  {log_label} attempt {attempt}/{max_retries} failed: {e}",
                file=sys.stderr,
            )
            if _classify_llm_error(e) == "no_retry":
                break
            if attempt < max_retries:
                time.sleep(_retry_backoff(attempt))
        except Exception as e:
            formatted_error = _format_provider_http_error(provider, e)
            last_error = RuntimeError(formatted_error)
            append_run_log_event(
                config,
                "llm_error",
                {
                    "label": log_label,
                    "task_type": task_type or "",
                    "attempt": attempt,
                    "error": formatted_error,
                },
            )
            print(
                f"⚠️  {log_label} attempt {attempt}/{max_retries} failed: {formatted_error}",
                file=sys.stderr,
            )
            if _classify_llm_error(e) == "no_retry":
                break
            if attempt < max_retries:
                time.sleep(_retry_backoff(attempt))

    raise RuntimeError(
        f"{log_label}: LLM call failed after {max_retries} attempts. Last error: {last_error}"
    )
