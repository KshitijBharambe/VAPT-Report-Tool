import base64
import io
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from report_runtime import py_adapter


class ReportRuntimePyAdapterTests(unittest.TestCase):
    def test_write_temp_upload_rejects_disallowed_suffix(self) -> None:
        payload = base64.b64encode(b"hello").decode("ascii")
        with self.assertRaises(ValueError):
            py_adapter._write_temp_upload("payload.exe", payload)

    def test_write_temp_upload_accepts_allowed_suffix(self) -> None:
        payload = base64.b64encode(b"a,b\n1,2\n").decode("ascii")
        out_path = py_adapter._write_temp_upload("input.csv", payload)
        try:
            self.assertEqual(out_path.suffix.lower(), ".csv")
            self.assertTrue(out_path.exists())
        finally:
            out_path.unlink(missing_ok=True)

    def test_default_output_path_sanitizes_client_and_stays_in_output_dir(self) -> None:
        out_path = py_adapter._default_output_path("../../evil client??")
        output_dir = py_adapter.OUTPUT_DIR.resolve()
        self.assertTrue(str(out_path).startswith(str(output_dir) + os.sep))
        self.assertNotIn("/", out_path.name)
        self.assertNotIn("..", out_path.name)
        self.assertIn("evil_client__", out_path.name)

    def test_resolve_template_path_rejects_path_outside_project(self) -> None:
        with self.assertRaisesRegex(ValueError, "project directory"):
            py_adapter._resolve_template_path("/tmp/outside-template.docx")

    def test_resolve_generate_template_path_requires_uploaded_template(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "Upload a \\.docx base template first",
        ):
            py_adapter._resolve_generate_template_path("")

    def test_resolve_generate_template_path_uses_uploaded_template(
        self,
    ) -> None:
        with patch.object(
            py_adapter,
            "_resolve_template_path",
            return_value=Path("template.docx"),
        ) as resolve_template_path:
            result = py_adapter._resolve_generate_template_path("template.docx")

        self.assertEqual(result, Path("template.docx"))
        resolve_template_path.assert_called_once_with("template.docx")

    def test_run_analyze_propagates_strict_validation_error(self) -> None:
        strict_error = ValueError(
            "Structured findings missing required source-of-truth fields: description"
        )
        payload = {
            "filename": "input.csv",
            "file_content_base64": base64.b64encode(b"x").decode("ascii"),
        }
        with patch.object(
            py_adapter, "_write_temp_upload", return_value=Path("input.csv")
        ):
            with patch.object(
                py_adapter.gr, "generate_per_vuln", side_effect=strict_error
            ):
                with self.assertRaises(ValueError):
                    py_adapter._run_analyze(payload)

    def test_run_analyze_success(self) -> None:
        payload = {
            "filename": "input.csv",
            "file_content_base64": base64.b64encode(b"x").decode("ascii"),
        }
        expected_data = {"findings": [{"id": "VAPT-001"}]}
        with patch.object(
            py_adapter, "_write_temp_upload", return_value=Path("input.csv")
        ), patch.object(
            py_adapter,
            "_list_run_logs",
            side_effect=[
                [],
                [Path("logs/20260422_120000_000001_run_log.json")],
            ],
        ), patch.object(
            py_adapter,
            "_count_llm_interactions",
            return_value=3,
        ):
            with patch.object(
                py_adapter.gr,
                "generate_per_vuln",
                return_value=(expected_data, ["raw"], [{"id": "FP-001"}]),
            ):
                result = py_adapter._run_analyze(payload)

        self.assertTrue(result["ok"])
        self.assertEqual(result["data"], expected_data)
        self.assertEqual(result["data"]["_input_name"], "input.csv")
        self.assertEqual(result["data"]["_source_file"], "input.csv")
        self.assertEqual(
            result["data"]["_run_log_path"],
            "logs/20260422_120000_000001_run_log.json",
        )
        self.assertEqual(result["data"]["_llm_interaction_count"], 3)
        self.assertEqual(result["data"]["false_positives"], [{"id": "FP-001"}])
        self.assertEqual(result["raw_count"], 1)
        self.assertEqual(result["false_positives"], [{"id": "FP-001"}])
        self.assertEqual(result["llm_interaction_count"], 3)
        self.assertEqual(
            result["run_log_path"],
            "logs/20260422_120000_000001_run_log.json",
        )

    def test_count_llm_interactions_reads_run_log_events(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            run_log_path = Path(tmp_dir) / "run_log.json"
            run_log_path.write_text(
                json.dumps(
                    {
                        "events": [
                            {"type": "llm_interaction"},
                            {"type": "structured_findings_derived"},
                            {"type": "llm_interaction"},
                        ]
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(py_adapter._count_llm_interactions(run_log_path), 2)

    def test_run_generate_success(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "report.docx"

            def _fake_render_report(*args, **kwargs):
                Path(kwargs["output_path"]).write_bytes(b"docx-bytes")

            payload = {
                "analysis_data": {"client_name": "Acme"},
                "template_path": "template.docx",
                "include_summary_table": True,
            }
            with patch.object(
                py_adapter, "_default_output_path", return_value=output_path
            ), patch.object(
                py_adapter,
                "_resolve_generate_template_path",
                return_value=Path("template.docx"),
            ):
                with patch.object(py_adapter.gr, "render_report", side_effect=_fake_render_report):
                    result = py_adapter._run_generate(payload)

        self.assertTrue(result["ok"])
        self.assertEqual(result["file_name"], "report.docx")
        self.assertEqual(base64.b64decode(result["docx_base64"]), b"docx-bytes")

    def test_main_health_check(self) -> None:
        stdin = io.StringIO(json.dumps({"action": "health"}))
        stdout = io.StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            rc = py_adapter.main()

        self.assertEqual(rc, 0)
        response = json.loads(stdout.getvalue())
        self.assertTrue(response["ok"])
        self.assertEqual(response["status"], "ok")

    def test_run_models_action(self) -> None:
        stdin = io.StringIO(
            json.dumps(
                {
                    "action": "models",
                    "provider": "local",
                    "base_url": "http://127.0.0.1:1234/v1",
                    "api_key": "",
                }
            )
        )
        stdout = io.StringIO()
        with patch.object(
            py_adapter,
            "fetch_models_for_provider",
            return_value=["qwen3.5-9b", "llama3.1"],
        ):
            with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
                rc = py_adapter.main()

        self.assertEqual(rc, 0)
        response = json.loads(stdout.getvalue())
        self.assertTrue(response["ok"])
        self.assertEqual(response["models"], ["qwen3.5-9b", "llama3.1"])


if __name__ == "__main__":
    unittest.main()
