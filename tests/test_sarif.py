"""Tests for the SARIF reporter."""

import json

import pytest

from src.rules.engine import Finding, Severity
from src.reporter.sarif_reporter import report_sarif


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(**overrides):
    defaults = dict(
        rule_id="unpinned-action",
        severity=Severity.HIGH,
        title="Unpinned action reference",
        description="Action 'actions/checkout@v3' is not pinned to a SHA.",
        file_path=".github/workflows/ci.yml",
        job_id="build",
        step_name="Checkout code",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# SARIF structure
# ---------------------------------------------------------------------------

class TestSarifStructure:
    def test_valid_json(self):
        output = report_sarif([_make_finding()])
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_sarif_version(self):
        parsed = json.loads(report_sarif([_make_finding()]))
        assert parsed["version"] == "2.1.0"

    def test_has_schema(self):
        parsed = json.loads(report_sarif([_make_finding()]))
        assert "$schema" in parsed

    def test_has_one_run(self):
        parsed = json.loads(report_sarif([_make_finding()]))
        assert len(parsed["runs"]) == 1

    def test_tool_name(self):
        parsed = json.loads(report_sarif([_make_finding()]))
        assert parsed["runs"][0]["tool"]["driver"]["name"] == "gha-guard"

    def test_empty_findings(self):
        parsed = json.loads(report_sarif([]))
        assert parsed["runs"][0]["results"] == []
        assert parsed["runs"][0]["tool"]["driver"]["rules"] == []


# ---------------------------------------------------------------------------
# Rules section
# ---------------------------------------------------------------------------

class TestSarifRules:
    def test_rule_id_present(self):
        parsed = json.loads(report_sarif([_make_finding()]))
        rule_ids = [r["id"] for r in parsed["runs"][0]["tool"]["driver"]["rules"]]
        assert "unpinned-action" in rule_ids

    def test_deduplicates_rules(self):
        findings = [
            _make_finding(rule_id="unpinned-action"),
            _make_finding(rule_id="unpinned-action"),
            _make_finding(rule_id="missing-permissions"),
        ]
        parsed = json.loads(report_sarif(findings))
        rule_ids = [r["id"] for r in parsed["runs"][0]["tool"]["driver"]["rules"]]
        assert rule_ids.count("unpinned-action") == 1
        assert len(rule_ids) == 2

    def test_rule_has_security_severity(self):
        parsed = json.loads(report_sarif([_make_finding(severity=Severity.CRITICAL)]))
        rule = parsed["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["security-severity"] == "9.0"

    def test_severity_mapping(self):
        for severity, expected_score in [
            (Severity.CRITICAL, "9.0"),
            (Severity.HIGH, "7.0"),
            (Severity.MEDIUM, "5.0"),
            (Severity.LOW, "3.0"),
        ]:
            parsed = json.loads(report_sarif([_make_finding(severity=severity)]))
            rule = parsed["runs"][0]["tool"]["driver"]["rules"][0]
            assert rule["properties"]["security-severity"] == expected_score


# ---------------------------------------------------------------------------
# Results section
# ---------------------------------------------------------------------------

class TestSarifResults:
    def test_result_count(self):
        findings = [_make_finding(), _make_finding(rule_id="missing-permissions")]
        parsed = json.loads(report_sarif(findings))
        assert len(parsed["runs"][0]["results"]) == 2

    def test_result_rule_id(self):
        parsed = json.loads(report_sarif([_make_finding(rule_id="script-injection")]))
        result = parsed["runs"][0]["results"][0]
        assert result["ruleId"] == "script-injection"

    def test_result_message(self):
        parsed = json.loads(report_sarif([_make_finding()]))
        result = parsed["runs"][0]["results"][0]
        assert "not pinned" in result["message"]["text"]

    def test_result_level_error_for_high(self):
        parsed = json.loads(report_sarif([_make_finding(severity=Severity.HIGH)]))
        assert parsed["runs"][0]["results"][0]["level"] == "error"

    def test_result_level_error_for_critical(self):
        parsed = json.loads(report_sarif([_make_finding(severity=Severity.CRITICAL)]))
        assert parsed["runs"][0]["results"][0]["level"] == "error"

    def test_result_level_warning_for_medium(self):
        parsed = json.loads(report_sarif([_make_finding(severity=Severity.MEDIUM)]))
        assert parsed["runs"][0]["results"][0]["level"] == "warning"

    def test_result_level_note_for_low(self):
        parsed = json.loads(report_sarif([_make_finding(severity=Severity.LOW)]))
        assert parsed["runs"][0]["results"][0]["level"] == "note"

    def test_result_file_path(self):
        parsed = json.loads(report_sarif([_make_finding()]))
        location = parsed["runs"][0]["results"][0]["locations"][0]
        assert location["physicalLocation"]["artifactLocation"]["uri"] == ".github/workflows/ci.yml"

    def test_result_logical_locations_job_and_step(self):
        parsed = json.loads(report_sarif([_make_finding(job_id="deploy", step_name="Push")]))
        logical = parsed["runs"][0]["results"][0]["locations"][0]["logicalLocations"]
        kinds = {loc["kind"] for loc in logical}
        assert "job" in kinds
        assert "step" in kinds

    def test_result_no_logical_locations_when_workflow_level(self):
        parsed = json.loads(report_sarif([_make_finding(job_id="", step_name="")]))
        logical = parsed["runs"][0]["results"][0]["locations"][0]["logicalLocations"]
        assert logical == []

    def test_result_uses_line_number_when_present(self):
        parsed = json.loads(report_sarif([_make_finding(line_number=42)]))
        region = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 42

    def test_result_falls_back_to_line_1_when_no_line_number(self):
        parsed = json.loads(report_sarif([_make_finding(line_number=None)]))
        region = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 1
