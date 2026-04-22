import json
import tempfile
import unittest
from pathlib import Path

from report_core.recommendation_templates import (
    get_recommendation,
    has_template_match,
    select_recommendation_template,
)
from report_tool.recommendation_store import (
    JsonRecommendationStoreBackend,
    RecommendationTemplateStoreError,
    build_recommendation_template_store,
)


class RecommendationStoreTests(unittest.TestCase):
    def test_default_store_loads_expected_template(self) -> None:
        store = build_recommendation_template_store()
        self.assertIn("cipher_weakness", store.templates)
        self.assertEqual(store.service_hardening["openssh"], "openssh_outdated")

    def test_loader_rejects_missing_required_keys(self) -> None:
        bad_payload = {
            "RECOMMENDATION_TEMPLATES": {"foo": "bar"},
            "SERVICE_HARDENING": {"openssh": "openssh_outdated"},
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "bad_store.json"
            path.write_text(json.dumps(bad_payload), encoding="utf-8")

            with self.assertRaises(RecommendationTemplateStoreError):
                build_recommendation_template_store(
                    JsonRecommendationStoreBackend(path)
                )


class RecommendationSelectionCompatibilityTests(unittest.TestCase):
    def test_ssh_cipher_selection_precedence(self) -> None:
        key, variables = select_recommendation_template("SSH Weak Cipher CBC Enabled")
        self.assertEqual(key, "ssh_weak_ciphers")
        self.assertEqual(variables, {})

    def test_deprecated_tls_selection_and_formatting(self) -> None:
        key, variables = select_recommendation_template(
            "TLS 1.0 and TLS 1.1 Deprecated Protocol Support"
        )
        self.assertEqual(key, "deprecated_tls")
        self.assertEqual(variables["deprecated_version"], "TLS 1.0 and 1.1")

        recommendation = get_recommendation("TLS 1.0 and TLS 1.1 Deprecated Protocol")
        self.assertIsNotNone(recommendation)
        self.assertIn("disable support for TLS 1.0 and 1.1", recommendation)

    def test_has_template_match_false_for_unknown_title(self) -> None:
        self.assertFalse(
            has_template_match("Custom internal naming issue without pattern")
        )


if __name__ == "__main__":
    unittest.main()
