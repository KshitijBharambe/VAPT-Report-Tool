import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from report_runtime import history_store


class ReportRuntimeHistoryStoreTests(unittest.TestCase):
    def test_legacy_json_migrates_into_sqlite_once_without_duplicates(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            legacy_path = tmp_path / "history.json"
            db_path = tmp_path / "history.sqlite3"
            legacy_payload = [
                {
                    "id": "hist-002",
                    "date": "2026-04-22T23:22:44.951Z",
                    "input_name": "second.xlsx",
                    "source_file": "runtime_upload_b.xlsx",
                    "finding_count": 3,
                    "file_name": "second.docx",
                    "report_path": "outputs/runtime_reports/second.docx",
                    "log_path": "logs/second_run_log.json",
                    "findings": [{"id": "VAPT-002"}],
                    "analysis_data": {"findings": [{"id": "VAPT-002"}]},
                },
                {
                    "id": "hist-001",
                    "date": "2026-04-21T23:22:44.951Z",
                    "input_name": "first.xlsx",
                    "source_file": "runtime_upload_a.xlsx",
                    "finding_count": 1,
                    "file_name": "first.docx",
                    "report_path": "outputs/runtime_reports/first.docx",
                    "log_path": "logs/first_run_log.json",
                    "findings": [{"id": "VAPT-001"}],
                    "analysis_data": {"findings": [{"id": "VAPT-001"}]},
                },
            ]
            legacy_path.write_text(json.dumps(legacy_payload), encoding="utf-8")

            first_read = history_store.list_entries(
                db_path=db_path,
                legacy_json_path=legacy_path,
            )
            second_read = history_store.list_entries(
                db_path=db_path,
                legacy_json_path=legacy_path,
            )

        self.assertEqual([item["id"] for item in first_read], ["hist-002", "hist-001"])
        self.assertEqual([item["id"] for item in second_read], ["hist-002", "hist-001"])

    def test_append_and_get_round_trip_full_history_payload(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            entry = {
                "id": "hist-123",
                "date": "2026-04-22T23:22:44.951Z",
                "input_name": "scan.xlsx",
                "source_file": "runtime_upload_xyz.xlsx",
                "finding_count": 2,
                "file_name": "report.docx",
                "report_path": "outputs/runtime_reports/report.docx",
                "log_path": "logs/run_log.json",
                "findings": [{"id": "VAPT-123", "name": "Example Finding"}],
                "analysis_data": {
                    "findings": [{"id": "VAPT-123", "name": "Example Finding"}],
                    "false_positives": [{"id": "FP-001"}],
                    "_run_log_path": "logs/run_log.json",
                },
            }

            history_store.append_entry(
                entry,
                db_path=tmp_path / "history.sqlite3",
                legacy_json_path=tmp_path / "history.json",
            )
            loaded = history_store.get_entry(
                "hist-123",
                db_path=tmp_path / "history.sqlite3",
                legacy_json_path=tmp_path / "history.json",
            )

        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded["id"], "hist-123")
        self.assertEqual(loaded["file_name"], "report.docx")
        self.assertEqual(loaded["findings"], [{"id": "VAPT-123", "name": "Example Finding"}])
        self.assertEqual(loaded["analysis_data"]["false_positives"], [{"id": "FP-001"}])
