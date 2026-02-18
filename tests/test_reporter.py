"""Tests for the reporter."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.parser import parse_workflow
from src.rules import run_all_rules
from src.reporter import report_console, report_json


FIXTURE = os.path.join(
    os.path.dirname(__file__),
    "fixtures/.github/workflows/insecure-example.yml",
)


def test_console_report():
    workflow = parse_workflow(FIXTURE)
    findings = run_all_rules(workflow)

    print("=== CONSOLE REPORT ===")
    report_console(findings, file_path=FIXTURE)


def test_json_report():
    workflow = parse_workflow(FIXTURE)
    findings = run_all_rules(workflow)

    print("=== JSON REPORT ===")
    output = report_json(findings)
    print(output)

    # Verify it's valid JSON
    import json
    parsed = json.loads(output)
    assert parsed["total"] == len(findings)
    print("\nJSON report is valid!")


if __name__ == "__main__":
    test_console_report()
    test_json_report()
