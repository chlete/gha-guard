"""Tests for the CLI."""

import os
import pytest
from click.testing import CliRunner

from src.cli import cli, EXIT_OK, EXIT_FINDINGS, EXIT_ERROR


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures/.github/workflows")
INSECURE_FIXTURE = os.path.join(FIXTURES_DIR, "insecure-example.yml")
SECURE_FIXTURE = os.path.join(FIXTURES_DIR, "secure-example.yml")


@pytest.fixture
def runner():
    return CliRunner()


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

class TestExitCodes:
    def test_exit_1_on_findings(self, runner):
        result = runner.invoke(cli, ["scan", INSECURE_FIXTURE])
        assert result.exit_code == EXIT_FINDINGS

    def test_exit_0_on_clean(self, runner):
        result = runner.invoke(cli, ["scan", SECURE_FIXTURE])
        assert result.exit_code == EXIT_OK
        assert "No security issues found" in result.output

    def test_exit_2_on_bad_path(self, runner):
        result = runner.invoke(cli, ["scan", "/nonexistent/path"])
        assert result.exit_code == EXIT_ERROR

    def test_exit_2_on_invalid_yaml(self, runner, tmp_path):
        bad_file = tmp_path / "bad.yml"
        bad_file.write_text("just a string")
        result = runner.invoke(cli, ["scan", str(bad_file)])
        assert result.exit_code == EXIT_ERROR
        assert "Error" in result.output


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_bad_path_shows_friendly_message(self, runner):
        result = runner.invoke(cli, ["scan", "/does/not/exist"])
        assert "Error" in result.output
        assert result.exit_code == EXIT_ERROR

    def test_enrich_without_api_key_shows_error(self, runner, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        result = runner.invoke(cli, ["scan", INSECURE_FIXTURE, "--enrich"])
        assert result.exit_code == EXIT_ERROR
        assert "ANTHROPIC_API_KEY" in result.output

    def test_empty_directory(self, runner, tmp_path):
        result = runner.invoke(cli, ["scan", str(tmp_path)])
        assert result.exit_code == EXIT_OK
        assert "No workflow files found" in result.output


# ---------------------------------------------------------------------------
# Output formats
# ---------------------------------------------------------------------------

class TestOutputFormats:
    def test_console_output(self, runner):
        result = runner.invoke(cli, ["scan", INSECURE_FIXTURE])
        assert "Unpinned action reference" in result.output

    def test_json_output(self, runner):
        result = runner.invoke(cli, ["scan", INSECURE_FIXTURE, "--format", "json"])
        import json
        parsed = json.loads(result.output)
        assert parsed["total"] > 0

    def test_directory_scan(self, runner):
        result = runner.invoke(cli, ["scan", FIXTURES_DIR])
        assert "Unpinned action reference" in result.output


# ---------------------------------------------------------------------------
# Severity filter
# ---------------------------------------------------------------------------

class TestSeverityFilter:
    def test_filter_critical_only(self, runner):
        result = runner.invoke(cli, ["scan", INSECURE_FIXTURE, "--severity", "critical", "--format", "json"])
        import json
        parsed = json.loads(result.output)
        for f in parsed["findings"]:
            assert f["severity"] == "critical"

    def test_filter_high_and_above(self, runner):
        result = runner.invoke(cli, ["scan", INSECURE_FIXTURE, "--severity", "high", "--format", "json"])
        import json
        parsed = json.loads(result.output)
        for f in parsed["findings"]:
            assert f["severity"] in ("high", "critical")


# ---------------------------------------------------------------------------
# Verbose flag
# ---------------------------------------------------------------------------

class TestVerbose:
    def test_verbose_flag_accepted(self, runner):
        result = runner.invoke(cli, ["-v", "scan", SECURE_FIXTURE])
        assert result.exit_code == EXIT_OK


# ---------------------------------------------------------------------------
# Config file integration
# ---------------------------------------------------------------------------

class TestConfigIntegration:
    def test_ignore_rules_from_config(self, runner, tmp_path):
        """Config ignore_rules should suppress matching findings."""
        import shutil
        shutil.copy(INSECURE_FIXTURE, tmp_path / "insecure-example.yml")
        cfg = tmp_path / ".gha-guard.yml"
        cfg.write_text(
            "ignore_rules:\n"
            "  - unpinned-action\n"
            "  - dangerous-trigger\n"
            "  - secret-in-run\n"
            "  - write-all-permissions\n"
            "  - script-injection\n"
            "  - missing-permissions\n"
            "  - manual-trigger\n"
        )
        result = runner.invoke(cli, [
            "scan", str(tmp_path / "insecure-example.yml"),
            "--config", str(cfg),
        ])
        assert result.exit_code == EXIT_OK
        assert "No security issues found" in result.output

    def test_severity_from_config(self, runner, tmp_path):
        """Config severity should filter findings."""
        import shutil
        shutil.copy(INSECURE_FIXTURE, tmp_path / "insecure-example.yml")
        cfg = tmp_path / ".gha-guard.yml"
        cfg.write_text("severity: critical\n")
        result = runner.invoke(cli, [
            "scan", str(tmp_path / "insecure-example.yml"),
            "--config", str(cfg),
            "--format", "json",
        ])
        import json
        parsed = json.loads(result.output)
        for f in parsed["findings"]:
            assert f["severity"] == "critical"

    def test_cli_severity_overrides_config(self, runner, tmp_path):
        """CLI --severity flag should override config file."""
        import shutil
        shutil.copy(INSECURE_FIXTURE, tmp_path / "insecure-example.yml")
        cfg = tmp_path / ".gha-guard.yml"
        cfg.write_text("severity: low\n")
        result = runner.invoke(cli, [
            "scan", str(tmp_path / "insecure-example.yml"),
            "--config", str(cfg),
            "--severity", "critical",
            "--format", "json",
        ])
        import json
        parsed = json.loads(result.output)
        for f in parsed["findings"]:
            assert f["severity"] == "critical"

    def test_exclude_from_config(self, runner, tmp_path):
        """Config exclude should skip matching workflow files."""
        import shutil
        wf_dir = tmp_path / "workflows"
        wf_dir.mkdir()
        shutil.copy(INSECURE_FIXTURE, wf_dir / "insecure-example.yml")
        shutil.copy(SECURE_FIXTURE, wf_dir / "secure-example.yml")
        cfg = tmp_path / ".gha-guard.yml"
        cfg.write_text("exclude:\n  - '**/insecure-*'\n")
        result = runner.invoke(cli, [
            "scan", str(wf_dir),
            "--config", str(cfg),
        ])
        assert result.exit_code == EXIT_OK
        assert "No security issues found" in result.output
