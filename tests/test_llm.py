"""Tests for the Claude LLM enrichment layer."""

import json
from unittest.mock import patch, MagicMock

import pytest

from src.rules.engine import Finding, Severity
from src.llm.claude_client import enrich_findings, _build_user_prompt, EnrichedFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(**overrides):
    defaults = dict(
        rule_id="unpinned-action",
        severity=Severity.HIGH,
        title="Unpinned action reference",
        description="Action 'actions/checkout@v3' is not pinned.",
        file_path="test.yml",
        job_id="build",
        step_name="Checkout code",
    )
    defaults.update(overrides)
    return Finding(**defaults)


SAMPLE_YAML = "name: Test\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"


def _mock_claude_response(explanation, suggested_fix):
    """Create a mock Anthropic API response."""
    response = MagicMock()
    content_block = MagicMock()
    content_block.text = json.dumps({
        "explanation": explanation,
        "suggested_fix": suggested_fix,
    })
    response.content = [content_block]
    return response


# ---------------------------------------------------------------------------
# _build_user_prompt
# ---------------------------------------------------------------------------

class TestBuildUserPrompt:
    def test_includes_rule_id(self):
        finding = _make_finding(rule_id="my-rule")
        prompt = _build_user_prompt(finding, SAMPLE_YAML)
        assert "my-rule" in prompt

    def test_includes_severity(self):
        finding = _make_finding(severity=Severity.CRITICAL)
        prompt = _build_user_prompt(finding, SAMPLE_YAML)
        assert "critical" in prompt

    def test_includes_workflow_yaml(self):
        prompt = _build_user_prompt(_make_finding(), SAMPLE_YAML)
        assert "name: Test" in prompt

    def test_includes_job_and_step(self):
        finding = _make_finding(job_id="deploy", step_name="Push image")
        prompt = _build_user_prompt(finding, SAMPLE_YAML)
        assert "deploy" in prompt
        assert "Push image" in prompt


# ---------------------------------------------------------------------------
# enrich_findings (mocked Claude API)
# ---------------------------------------------------------------------------

class TestEnrichFindings:
    @patch("src.llm.claude_client.Anthropic")
    def test_returns_enriched_findings(self, mock_anthropic_cls):
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.return_value = _mock_claude_response(
            "This is dangerous because...",
            "uses: actions/checkout@abc123...",
        )

        findings = [_make_finding()]
        enriched = enrich_findings(findings, SAMPLE_YAML, api_key="fake-key")

        assert len(enriched) == 1
        assert enriched[0].explanation == "This is dangerous because..."
        assert enriched[0].suggested_fix == "uses: actions/checkout@abc123..."
        assert enriched[0].finding == findings[0]

    @patch("src.llm.claude_client.Anthropic")
    def test_handles_multiple_findings(self, mock_anthropic_cls):
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.return_value = _mock_claude_response(
            "Explanation", "Fix"
        )

        findings = [_make_finding(), _make_finding(rule_id="other-rule")]
        enriched = enrich_findings(findings, SAMPLE_YAML, api_key="fake-key")

        assert len(enriched) == 2
        assert mock_client.messages.create.call_count == 2

    @patch("src.llm.claude_client.Anthropic")
    def test_handles_invalid_json_response(self, mock_anthropic_cls):
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client

        response = MagicMock()
        content_block = MagicMock()
        content_block.text = "This is not JSON, just plain text."
        response.content = [content_block]
        mock_client.messages.create.return_value = response

        findings = [_make_finding()]
        enriched = enrich_findings(findings, SAMPLE_YAML, api_key="fake-key")

        assert len(enriched) == 1
        assert enriched[0].explanation == "This is not JSON, just plain text."
        assert enriched[0].suggested_fix == "Could not parse fix suggestion."

    def test_raises_without_api_key(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(ValueError, match="No Anthropic API key"):
            enrich_findings([_make_finding()], SAMPLE_YAML)
