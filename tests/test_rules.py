"""Tests for the security rules."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.parser import parse_workflow
from src.rules import run_all_rules, Severity


FIXTURE = os.path.join(
    os.path.dirname(__file__),
    "fixtures/.github/workflows/insecure-example.yml",
)


def test_all_rules():
    workflow = parse_workflow(FIXTURE)
    findings = run_all_rules(workflow)

    # Collect rule IDs
    rule_ids = [f.rule_id for f in findings]

    # We expect at least these findings from our insecure fixture:
    assert "unpinned-action" in rule_ids, "Should detect unpinned actions"
    assert "write-all-permissions" in rule_ids, "Should detect write-all permissions"
    assert "script-injection" in rule_ids, "Should detect script injection"
    assert "dangerous-trigger" in rule_ids, "Should detect pull_request_target"
    assert "secret-in-run" in rule_ids, "Should detect secrets in run blocks"

    # Print all findings for visibility
    print(f"\nFound {len(findings)} findings:\n")
    for f in findings:
        print(f"  [{f.severity.value.upper():8s}] {f.rule_id}")
        print(f"           {f.title}")
        print(f"           Job: {f.job_id or '(workflow-level)'}, Step: {f.step_name or 'N/A'}")
        print()

    print("All rule assertions passed!")


if __name__ == "__main__":
    test_all_rules()
