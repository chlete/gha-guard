"""Tests for the reporters."""

import json
import pytest

from src.rules.engine import Finding, Severity
from src.reporter import report_console, report_json
from src.reporter.enriched_reporter import report_enriched
from src.llm.claude_client import EnrichedFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(**overrides):
    defaults = dict(
        rule_id="test-rule",
        severity=Severity.HIGH,
        title="Test finding",
        description="A test description.",
        file_path="test.yml",
        job_id="build",
        step_name="test-step",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Console reporter
# ---------------------------------------------------------------------------

class TestConsoleReporter:
    def test_includes_finding_title(self, insecure_findings):
        output = report_console(insecure_findings, file_path="test.yml")
        assert "Unpinned action reference" in output

    def test_includes_severity(self, insecure_findings):
        output = report_console(insecure_findings)
        assert "CRITICAL" in output
        assert "HIGH" in output

    def test_includes_summary_count(self, insecure_findings):
        output = report_console(insecure_findings)
        assert "7" in output

    def test_empty_findings(self):
        output = report_console([], file_path="test.yml")
        assert "No security issues found" in output

    def test_includes_file_path(self):
        output = report_console([], file_path="/path/to/workflow.yml")
        assert "/path/to/workflow.yml" in output


# ---------------------------------------------------------------------------
# JSON reporter
# ---------------------------------------------------------------------------

class TestJsonReporter:
    def test_valid_json(self, insecure_findings):
        output = report_json(insecure_findings)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_total_count(self, insecure_findings):
        parsed = json.loads(report_json(insecure_findings))
        assert parsed["total"] == 7

    def test_finding_fields(self):
        finding = _make_finding(rule_id="my-rule", title="My Title")
        parsed = json.loads(report_json([finding]))
        f = parsed["findings"][0]
        assert f["rule_id"] == "my-rule"
        assert f["title"] == "My Title"
        assert f["severity"] == "high"

    def test_empty_findings(self):
        parsed = json.loads(report_json([]))
        assert parsed["total"] == 0
        assert parsed["findings"] == []


# ---------------------------------------------------------------------------
# Enriched reporter
# ---------------------------------------------------------------------------

class TestEnrichedReporter:
    def _make_enriched(self, **finding_overrides):
        return EnrichedFinding(
            finding=_make_finding(**finding_overrides),
            explanation="This is risky because...",
            suggested_fix="uses: actions/checkout@abc123...",
        )

    def test_includes_explanation(self):
        ef = self._make_enriched()
        output = report_enriched([ef])
        assert "This is risky because" in output

    def test_includes_suggested_fix(self):
        ef = self._make_enriched()
        output = report_enriched([ef])
        assert "actions/checkout@abc123" in output

    def test_includes_ai_enhanced_header(self):
        ef = self._make_enriched()
        output = report_enriched([ef])
        assert "AI-Enhanced" in output

    def test_empty_findings(self):
        output = report_enriched([])
        assert "No security issues found" in output
