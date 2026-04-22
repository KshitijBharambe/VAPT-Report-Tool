"""Smoke tests for quality scoring + reference validation + priority sort."""

from __future__ import annotations

from report_tool.quality.references import (
    _ref_priority,
    validate_finding_refs,
    validate_report_refs,
)
from report_tool.quality.scorer import score_finding, score_report


def test_priority_ranking_nvd_highest():
    assert _ref_priority("https://nvd.nist.gov/vuln/detail/CVE-2024-0001") < _ref_priority(
        "https://cwe.mitre.org/data/definitions/79.html"
    )
    assert _ref_priority("https://cwe.mitre.org/data/definitions/79.html") < _ref_priority(
        "https://msrc.microsoft.com/update-guide"
    )
    assert _ref_priority("https://msrc.microsoft.com/foo") < _ref_priority(
        "https://owasp.org/www-project-top-ten/"
    )
    assert _ref_priority("https://owasp.org/x") < _ref_priority(
        "https://example.com/blog/post"
    )


def test_validate_finding_refs_sorted_by_priority(monkeypatch):
    # Stub the network check to always succeed
    from report_tool.quality import references as refs_mod

    monkeypatch.setattr(refs_mod, "_check_url", lambda url, timeout=8.0: (True, 200))

    finding = {
        "cve": "CVE-2024-0001",
        "reference": [
            {"title": "Generic", "url": "https://www.python.org/downloads/security/"},
            {"title": "OWASP", "url": "https://owasp.org/x"},
            {"title": "MS", "url": "https://msrc.microsoft.com/adv"},
        ],
    }
    out = validate_finding_refs(finding, add_canonical=True)
    urls = [r["url"] for r in out["reference"]]
    # NVD canonical should be first
    assert urls[0].startswith("https://nvd.nist.gov/")
    # generic refs must rank after OWASP
    assert urls.index("https://owasp.org/x") < urls.index("https://www.python.org/downloads/security/")


def test_validate_finding_refs_skips_network_for_non_public_targets():
    finding = {
        "reference": [
            {"title": "Internal", "url": "https://portal.client.local/advisory"},
        ]
    }

    out = validate_finding_refs(finding, add_canonical=False)
    assert out["reference"] == [{"title": "Internal", "url": "https://portal.client.local/advisory"}]


def test_score_finding_flags_generic():
    f = {
        "name": "Example",
        "description": "Update the software to latest version.",
        "remediation": "Apply patches.",
        "control_objective": "Apply patches.",
        "control_name": "",
        "audit_requirement": "",
    }
    s = score_finding(f)
    assert s["overall"] < 0.5
    assert any(flag.startswith("generic:") for flag in s["flags"])


def test_score_report_summary():
    report = {
        "findings": [
            {
                "name": "Good",
                "description": "A" * 100,
                "remediation": {"primary": "x" * 80, "secondary": "y" * 80, "defensive": "z" * 80},
                "control_objective": "o" * 80,
                "control_name": "Access control",
                "audit_requirement": "a" * 80,
                "cve": "CVE-2024-0001",
                "cvss": "7.5",
                "reference": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"}, {"url": "https://cwe.mitre.org/data/definitions/79.html"}],
            }
        ]
    }
    summary = score_report(report, min_pass=0.5)
    assert summary["count"] == 1
    assert summary["mean"] > 0.5
