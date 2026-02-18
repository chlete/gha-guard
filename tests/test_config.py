"""Tests for the configuration file support."""

import os
import pytest

from src.config import load_config, Config


# ---------------------------------------------------------------------------
# load_config with no file
# ---------------------------------------------------------------------------

class TestConfigDefaults:
    def test_returns_defaults_when_no_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        config = load_config()
        assert config.severity == "low"
        assert config.ignore_rules == []
        assert config.exclude == []

    def test_returns_defaults_for_invalid_yaml(self, tmp_path):
        cfg = tmp_path / ".gha-guard.yml"
        cfg.write_text("just a string")
        config = load_config(config_path=str(cfg))
        assert config.severity == "low"


# ---------------------------------------------------------------------------
# load_config with explicit path
# ---------------------------------------------------------------------------

class TestConfigExplicitPath:
    def test_loads_severity(self, tmp_path):
        cfg = tmp_path / ".gha-guard.yml"
        cfg.write_text("severity: high\n")
        config = load_config(config_path=str(cfg))
        assert config.severity == "high"

    def test_loads_ignore_rules(self, tmp_path):
        cfg = tmp_path / ".gha-guard.yml"
        cfg.write_text("ignore_rules:\n  - unpinned-action\n  - manual-trigger\n")
        config = load_config(config_path=str(cfg))
        assert config.ignore_rules == ["unpinned-action", "manual-trigger"]

    def test_loads_exclude(self, tmp_path):
        cfg = tmp_path / ".gha-guard.yml"
        cfg.write_text("exclude:\n  - '**/test-*.yml'\n")
        config = load_config(config_path=str(cfg))
        assert config.exclude == ["**/test-*.yml"]

    def test_loads_full_config(self, tmp_path):
        cfg = tmp_path / ".gha-guard.yml"
        cfg.write_text(
            "severity: critical\n"
            "ignore_rules:\n"
            "  - manual-trigger\n"
            "exclude:\n"
            "  - legacy.yml\n"
        )
        config = load_config(config_path=str(cfg))
        assert config.severity == "critical"
        assert config.ignore_rules == ["manual-trigger"]
        assert config.exclude == ["legacy.yml"]

    def test_missing_explicit_path_returns_defaults(self, tmp_path):
        config = load_config(config_path=str(tmp_path / "nonexistent.yml"))
        assert config.severity == "low"


# ---------------------------------------------------------------------------
# load_config auto-discovery via scan_path
# ---------------------------------------------------------------------------

class TestConfigAutoDiscovery:
    def test_finds_config_in_scan_dir(self, tmp_path):
        cfg = tmp_path / ".gha-guard.yml"
        cfg.write_text("severity: medium\n")
        config = load_config(scan_path=str(tmp_path))
        assert config.severity == "medium"

    def test_finds_config_in_parent_dir(self, tmp_path):
        cfg = tmp_path / ".gha-guard.yml"
        cfg.write_text("severity: high\n")
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        config = load_config(scan_path=str(workflows_dir))
        assert config.severity == "high"

    def test_finds_config_from_file_path(self, tmp_path):
        cfg = tmp_path / ".gha-guard.yml"
        cfg.write_text("severity: critical\n")
        wf_file = tmp_path / "ci.yml"
        wf_file.write_text("name: CI\n")
        config = load_config(scan_path=str(wf_file))
        assert config.severity == "critical"

    def test_cwd_fallback(self, tmp_path, monkeypatch):
        cfg = tmp_path / ".gha-guard.yml"
        cfg.write_text("severity: medium\n")
        monkeypatch.chdir(tmp_path)
        config = load_config()
        assert config.severity == "medium"
