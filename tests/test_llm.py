"""Tests for the Claude LLM enrichment layer."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.parser import parse_workflow
from src.rules import run_all_rules
from src.llm import enrich_findings
from src.reporter import report_enriched


FIXTURE = os.path.join(
    os.path.dirname(__file__),
    "fixtures/.github/workflows/insecure-example.yml",
)


def test_enrich_findings():
    # Check for API key
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("⚠ ANTHROPIC_API_KEY not set — skipping LLM test.")
        print("  Set it with: export ANTHROPIC_API_KEY=your-key-here")
        return

    # Parse and run rules
    workflow = parse_workflow(FIXTURE)
    findings = run_all_rules(workflow)

    # Read the raw YAML to send to Claude
    with open(FIXTURE, "r") as f:
        workflow_yaml = f.read()

    # Enrich with Claude (only first 2 findings to save API cost)
    print(f"Enriching {min(2, len(findings))} of {len(findings)} findings with Claude...\n")
    enriched = enrich_findings(findings[:2], workflow_yaml)

    assert len(enriched) == 2
    for ef in enriched:
        assert ef.explanation, "Explanation should not be empty"
        assert ef.suggested_fix, "Fix should not be empty"

    # Print the enriched report
    report_enriched(enriched, file_path=FIXTURE)
    print("LLM enrichment test passed!")


if __name__ == "__main__":
    test_enrich_findings()
