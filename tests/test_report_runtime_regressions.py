import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import generate_report as gr
from report_core.privacy import (
    ClientDataInternetEgressError,
    assert_safe_for_egress,
    prepare_client_context_for_cloud,
    sanitize_finding,
)
import report_tool.llm as llm
from report_tool.lookup import cloud_enrich


class ReportRuntimeRegressionTests(unittest.TestCase):
    def test_structured_cloud_lookup_uses_runtime_model(self) -> None:
        cfg = {
            "llm": {
                "provider": "openrouter",
                "model": "openai/oss-120b",
                "api_key": "runtime-key",
            }
        }

        cloud_cfg = gr._resolve_structured_cloud_lookup_cfg(cfg)

        self.assertIsNotNone(cloud_cfg)
        assert cloud_cfg is not None
        self.assertTrue(cloud_cfg["enabled"])
        self.assertEqual(cloud_cfg["api_key"], "runtime-key")
        self.assertEqual(cloud_cfg["model"], "openai/oss-120b")

    def test_structured_cloud_lookup_prefers_task_model_override(self) -> None:
        cfg = {
            "llm": {
                "provider": "openrouter",
                "model": "openai/oss-120b",
                "api_key": "runtime-key",
                "task_models": {"lookup": "anthropic/claude-sonnet-4"},
            }
        }

        cloud_cfg = gr._resolve_structured_cloud_lookup_cfg(cfg)

        self.assertIsNotNone(cloud_cfg)
        assert cloud_cfg is not None
        self.assertEqual(cloud_cfg["model"], "anthropic/claude-sonnet-4")

    def test_structured_cloud_lookup_disabled_for_local_provider(self) -> None:
        cfg = {
            "llm": {
                "provider": "local",
                "model": "qwen3",
                "api_key": "session-key",
                "base_url": "http://127.0.0.1:1234/v1",
            }
        }

        self.assertIsNone(gr._resolve_structured_cloud_lookup_cfg(cfg))

    def test_structured_second_stage_defaults_to_disabled_after_cloud_lookup(self) -> None:
        cfg = {
            "llm": {
                "provider": "openrouter",
                "model": "openai/gpt-oss-120b:free",
                "api_key": "session-key",
            }
        }

        self.assertFalse(
            gr._should_run_structured_second_stage(
                cfg,
                {"cloud_eligible_findings": 3},
            )
        )

    def test_structured_second_stage_can_be_explicitly_enabled(self) -> None:
        cfg = {
            "llm": {
                "provider": "openrouter",
                "model": "openai/gpt-oss-120b:free",
                "api_key": "session-key",
            },
            "structured_lookup": {"second_stage_enabled": True},
        }

        self.assertTrue(
            gr._should_run_structured_second_stage(
                cfg,
                {"cloud_eligible_findings": 3},
            )
        )

    def test_per_vuln_progress_message_includes_current_vuln(self) -> None:
        message = gr._build_per_vuln_progress_message(
            completed=3,
            total=10,
            candidate={
                "vuln_id": 42,
                "short_name": "TLS Version 1.1 Deprecated Protocol",
            },
        )

        self.assertIn("3/10", message)
        self.assertIn("42", message)
        self.assertIn("TLS Version 1.1", message)

    def test_display_title_strips_leading_nessus_plugin_id(self) -> None:
        self.assertEqual(
            gr._display_title_from_finding({"name": "[11411] Backup Files Disclosure"}),
            "Backup Files Disclosure",
        )

    def test_lookup_report_uses_cached_result_without_batch_call(self) -> None:
        finding = {
            "id": "VAPT-001",
            "name": "SNMP Service Default Community String",
            "severity": "High",
            "description": "SNMP public community string is enabled.",
        }
        cached = {
            "control_objective": "Restrict administrative access to approved protocols and secrets.",
            "control_name": "SNMP Access Hardening",
            "audit_requirement": "Verify default SNMP community strings are disabled and custom values are rotated.",
            "recommendation": {
                "primary": "Disable default SNMP community strings and replace them with strong unique values.",
                "secondary": "If replacement is not possible immediately, restrict SNMP access to trusted hosts only.",
                "defensive": "Enable monitoring for unexpected SNMP queries and authentication failures.",
            },
        }

        with patch.object(cloud_enrich, "_lookup_cves", return_value=[]), patch.object(
            cloud_enrich, "_collect_cwe_ids", return_value=[]
        ), patch.object(
            cloud_enrich.rec_db, "lookup", return_value=cached
        ), patch.object(
            cloud_enrich, "_call_openrouter_batch"
        ) as batch_call:
            data = cloud_enrich.lookup_report(
                {"findings": [finding]},
                {
                    "enabled": True,
                    "api_key": "session-key",
                    "model": "openai/gpt-oss-120b:free",
                },
            )

        self.assertEqual(len(data["findings"]), 1)
        resolved = data["findings"][0]
        self.assertEqual(
            resolved["control_name"],
            "SNMP Access Hardening",
        )
        self.assertEqual(
            resolved["audit_requirement"],
            "Verify default SNMP community strings are disabled and custom values are rotated.",
        )
        self.assertEqual(
            resolved["recommendation"]["primary"],
            "Disable default SNMP community strings and replace them with strong unique values.",
        )
        batch_call.assert_not_called()

    def test_lookup_report_progress_tracks_exact_active_vulnerability(self) -> None:
        findings = [
            {
                "id": "VAPT-001",
                "name": "TLS Version 1.0 Deprecated Protocol",
                "severity": "Medium",
                "description": "TLS 1.0 is enabled.",
            },
            {
                "id": "VAPT-002",
                "name": "SMB Signing Disabled",
                "severity": "High",
                "description": "SMB signing is disabled.",
            },
        ]
        events: list[tuple[int, int, str, dict | None]] = []

        def _record_progress(current, total, message="", detail=None):
            events.append((current, total, message, detail))

        def _fake_batch(payload, _cloud_cfg):
            item = payload[0]
            return {
                "results": [
                    {
                        "key": item["key"],
                        "control_objective": "Test objective",
                        "control_name": "Test control",
                        "audit_requirement": "Test audit",
                        "recommendation": {
                            "primary": "Primary fix",
                            "secondary": "Secondary fix",
                            "defensive": "Defensive control",
                        },
                        "reference": [],
                    }
                ]
            }

        with patch.object(cloud_enrich, "_lookup_cves", return_value=[]), patch.object(
            cloud_enrich, "_collect_cwe_ids", return_value=[]
        ), patch.object(
            cloud_enrich.rec_db, "lookup", return_value=None
        ), patch.object(
            cloud_enrich, "_call_openrouter_batch", side_effect=_fake_batch
        ) as batch_call:
            cloud_enrich.lookup_report(
                {"findings": findings},
                {
                    "enabled": True,
                    "api_key": "session-key",
                    "model": "openai/gpt-oss-120b:free",
                },
                on_progress=_record_progress,
            )

        self.assertEqual(batch_call.call_count, 1)
        self.assertGreaterEqual(len(events), 2)
        self.assertEqual(
            events[0][0:3],
            (
                1,
                2,
                "Cloud lookup 1-2/2: TLS Version 1.0 Deprecated Protocol; SMB Signing Disabled",
            ),
        )
        self.assertEqual(
            events[0][3],
            {
                "phase": "cloud_lookup",
                "active_label": "",
                "active_items": [
                    "TLS Version 1.0 Deprecated Protocol",
                    "SMB Signing Disabled",
                ],
                "completed": 0,
                "batch_size": 2,
            },
        )
        self.assertEqual(
            events[-1][0:3],
            (2, 2, "Cloud lookup complete — 2/2 eligible findings processed (2 total findings)."),
        )

    def test_assert_safe_for_egress_ignores_schema_field_tokens(self) -> None:
        assert_safe_for_egress(
            {
                "messages": [
                    {
                        "role": "system",
                        "content": "Return recommendation.primary, recommendation.secondary, and reference.url fields.",
                    }
                ]
            }
        )

    def test_assert_safe_for_egress_allows_testssl_tool_token(self) -> None:
        assert_safe_for_egress(
            {
                "messages": [
                    {
                        "role": "system",
                        "content": "Verify SSL/TLS configuration using a TLS scanner (e.g., testssl.sh).",
                    }
                ]
            }
        )

    def test_sanitize_finding_masks_nested_host_data(self) -> None:
        finding = {
            "name": "Portal host portal.client.local exposes weak TLS",
            "description": "Weak TLS remains enabled on portal.client.local.",
            "reference": [
                {
                    "title": "Internal guide for portal.client.local",
                    "url": "https://portal.client.local/hardening",
                }
            ],
        }

        sanitized, restore_map = sanitize_finding(finding)

        self.assertNotIn("portal.client.local", json.dumps(sanitized))
        self.assertTrue(any(original == "portal.client.local" for original in restore_map.values()))

    def test_openrouter_missing_key_error_mentions_session_only_flow(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "session"):
            cloud_enrich._call_openrouter(
                [{"role": "user", "content": "hi"}],
                {"enabled": True, "model": "openai/gpt-oss-120b:free"},
            )

    def test_generate_per_vuln_allows_cloud_provider_with_session_key(self) -> None:
        cfg = {
            "llm": {
                "provider": "openrouter",
                "model": "openai/gpt-oss-120b:free",
                "base_url": "https://openrouter.ai/api/v1",
                "api_key": "session-key",
            },
            "paths": {"log_dir": "logs"},
        }

        with patch.object(gr, "load_config", return_value=cfg), patch.object(
            gr,
            "_generate_from_structured_file",
            return_value=("ok", [], []),
        ):
            result = gr.generate_per_vuln("input.xlsx", config_path="ignored")
        self.assertEqual(result, ("ok", [], []))

    def test_prepare_client_context_for_cloud_auto_sanitizes_raw_context(self) -> None:
        cfg = {
            "llm": {
                "provider": "openrouter",
                "model": "openai/gpt-oss-120b:free",
                "base_url": "https://openrouter.ai/api/v1",
                "api_key": "session-key",
                "max_retries": 1,
            },
            "paths": {"log_dir": "logs"},
        }
        sanitized, restore_map = prepare_client_context_for_cloud(
            "Client: Example Corp\nScope: 10.0.0.5",
            cfg,
        )
        self.assertNotIn("Example Corp", sanitized)
        self.assertNotIn("10.0.0.5", sanitized)
        self.assertIn("[CLIENT_1]", sanitized)
        self.assertIn("[CONTEXT_1]", sanitized)
        self.assertIn("Example Corp", restore_map.values())

    def test_call_llm_generic_sanitizes_cloud_payload_before_network(self) -> None:
        captured = {}

        class FakeResponse:
            def raise_for_status(self):
                return None

            def iter_lines(self):
                yield 'data: {"choices":[{"delta":{"content":"{\\"client\\":\\"[CLIENT_1]\\",\\"asset\\":\\"[URL_1]\\"}"}}]}'
                yield "data: [DONE]"

        class FakeStream:
            def __enter__(self):
                return FakeResponse()

            def __exit__(self, exc_type, exc, tb):
                return False

        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def stream(self, method, url, json=None, headers=None):
                captured["payload"] = json
                return FakeStream()

        with TemporaryDirectory() as tmp_dir, patch("httpx.Client", FakeClient):
            cfg = {
                "llm": {
                    "provider": "openrouter",
                    "model": "openai/gpt-oss-120b:free",
                    "base_url": "https://openrouter.ai/api/v1",
                    "api_key": "session-key",
                    "max_retries": 1,
                },
                "paths": {"log_dir": tmp_dir},
            }

            result = llm._call_llm_generic(
                "system",
                "Client: Example Corp\nTarget URL: https://portal.client.local/app",
                cfg,
                log_label="structured_lookup_1",
                task_type="lookup",
            )
        outbound = captured["payload"]["messages"][1]["content"]
        self.assertNotIn("Example Corp", outbound)
        self.assertNotIn("portal.client.local", outbound)
        self.assertIn("[CLIENT_1]", outbound)
        self.assertIn("[URL_1]", outbound)
        self.assertIn("Example Corp", result)
        self.assertIn("https://portal.client.local/app", result)

    def test_call_llm_generic_appends_all_interactions_to_single_run_log(self) -> None:
        responses = iter(
            [
                '{"client":"[CLIENT_1]","asset":"[URL_1]","seq":1}',
                '{"client":"[CLIENT_1]","asset":"[URL_1]","seq":2}',
            ]
        )

        class FakeResponse:
            def __init__(self, body: str):
                self._body = body

            def raise_for_status(self):
                return None

            def iter_lines(self):
                yield (
                    'data: {"choices":[{"delta":{"content":"'
                    + self._body.replace('"', '\\"')
                    + '"}}]}'
                )
                yield "data: [DONE]"

        class FakeStream:
            def __init__(self, body: str):
                self._body = body

            def __enter__(self):
                return FakeResponse(self._body)

            def __exit__(self, exc_type, exc, tb):
                return False

        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def stream(self, method, url, json=None, headers=None):
                return FakeStream(next(responses))

        with TemporaryDirectory() as tmp_dir, patch("httpx.Client", FakeClient):
            cfg = {
                "llm": {
                    "provider": "openrouter",
                    "model": "openai/gpt-oss-120b:free",
                    "base_url": "https://openrouter.ai/api/v1",
                    "api_key": "session-key",
                    "max_retries": 1,
                },
                "paths": {"log_dir": tmp_dir},
            }

            first = llm._call_llm_generic(
                "system",
                "Client: Example Corp\nTarget URL: https://portal.client.local/app",
                cfg,
                log_label="structured_lookup_1",
                task_type="lookup",
            )
            second = llm._call_llm_generic(
                "system",
                "Client: Example Corp\nTarget URL: https://portal.client.local/app",
                cfg,
                log_label="structured_lookup_2",
                task_type="lookup",
            )

            log_files = list(Path(tmp_dir).glob("*_run_log.json"))
            self.assertEqual(len(log_files), 1)
            self.assertEqual(list(Path(tmp_dir).glob("*_raw_llm_response.json")), [])

            payload = json.loads(log_files[0].read_text(encoding="utf-8"))

        interactions = [
            event for event in payload["events"] if event.get("type") == "llm_interaction"
        ]
        self.assertEqual(len(interactions), 2)
        self.assertEqual(interactions[0]["data"]["label"], "structured_lookup_1")
        self.assertEqual(interactions[1]["data"]["label"], "structured_lookup_2")
        self.assertIn("[CLIENT_1]", interactions[0]["data"]["user_content_sent"])
        self.assertIn("Example Corp", interactions[0]["data"]["user_content_original"])
        self.assertIn("portal.client.local", interactions[0]["data"]["response_restored"])
        self.assertEqual(json.loads(first)["seq"], 1)
        self.assertEqual(json.loads(second)["seq"], 2)

    def test_call_openrouter_batch_logs_request_and_response(self) -> None:
        captured = {}

        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return {
                    "choices": [
                        {
                            "message": {
                                "content": '{"results":[{"key":"f1","control_name":"Protect [HOST_1]"}]}'
                            }
                        }
                    ]
                }

        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def post(self, url, headers=None, json=None):
                captured["payload"] = json
                return FakeResponse()

        with TemporaryDirectory() as tmp_dir, patch("httpx.Client", FakeClient):
            cfg = {
                "enabled": True,
                "api_key": "session-key",
                "model": "openai/gpt-oss-120b:free",
                "paths": {"log_dir": tmp_dir},
            }

            parsed = cloud_enrich._call_openrouter_batch(
                [
                    {
                        "key": "f1",
                        "title": "TLS Weak Cipher on portal.client.local",
                        "severity": "Medium",
                        "description": "Weak ciphers remain enabled on portal.client.local.",
                        "style_examples": "Prior report for portal.client.local",
                    }
                ],
                cfg,
            )

            log_files = list(Path(tmp_dir).glob("*_run_log.json"))
            self.assertEqual(len(log_files), 1)
            payload = json.loads(log_files[0].read_text(encoding="utf-8"))

        self.assertEqual(
            parsed,
            {"results": [{"key": "f1", "control_name": "Protect portal.client.local"}]},
        )
        outbound = json.dumps(captured["payload"], ensure_ascii=False)
        self.assertNotIn("portal.client.local", outbound)
        self.assertIn("[HOST_1]", outbound)
        interactions = [
            event for event in payload["events"] if event.get("type") == "llm_interaction"
        ]
        self.assertEqual(len(interactions), 1)
        self.assertEqual(interactions[0]["data"]["label"], "cloud_lookup_batch")
        self.assertIn("[HOST_1]", interactions[0]["data"]["user_content_sent"])
        self.assertIn("portal.client.local", interactions[0]["data"]["user_content_original"])
        self.assertIn('"results"', interactions[0]["data"]["response_received_raw"])
        self.assertIn("portal.client.local", interactions[0]["data"]["response_restored"])


if __name__ == "__main__":
    unittest.main()
