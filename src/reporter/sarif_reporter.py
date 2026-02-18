"""
SARIF reporter: outputs findings in SARIF 2.1.0 format for GitHub Code Scanning.

SARIF (Static Analysis Results Interchange Format) is a JSON standard that
GitHub's Code Scanning feature understands. Upload the output to GitHub and
findings appear as annotations directly on the PR diff in the Security tab.

Reference: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
"""

import json
import logging
from typing import Any

from src.rules.engine import Finding, Severity

logger = logging.getLogger(__name__)

# Map our severity levels to SARIF notification levels
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

# Map our severity levels to SARIF security-severity scores (CVSS-like 0.0–10.0)
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "7.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
}

TOOL_NAME = "gha-guard"
TOOL_VERSION = "0.1.0"
TOOL_URI = "https://github.com/chlete/gha-guard"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"


def _build_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    """Build the SARIF rules array — one entry per unique rule ID."""
    seen: dict[str, Finding] = {}
    for f in findings:
        if f.rule_id not in seen:
            seen[f.rule_id] = f

    rules = []
    for rule_id, f in seen.items():
        rules.append({
            "id": rule_id,
            "name": rule_id.replace("-", " ").title().replace(" ", ""),
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.title},
            "helpUri": f"{TOOL_URI}#rule-{rule_id}",
            "properties": {
                "security-severity": _SECURITY_SEVERITY[f.severity],
                "tags": ["security", "github-actions"],
            },
        })
    return rules


def _build_result(f: Finding) -> dict[str, Any]:
    """Build a single SARIF result object from a Finding."""
    result: dict[str, Any] = {
        "ruleId": f.rule_id,
        "level": _SARIF_LEVEL[f.severity],
        "message": {"text": f.description},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.file_path,
                        "uriBaseId": "%SRCROOT%",
                    },
                    # SARIF requires a region; we don't have line numbers so
                    # we point to the start of the file
                    "region": {"startLine": 1},
                },
                "logicalLocations": _build_logical_locations(f),
            }
        ],
    }
    return result


def _build_logical_locations(f: Finding) -> list[dict[str, str]]:
    """Build logical location entries (job / step) for a finding."""
    locations = []
    if f.job_id:
        locations.append({
            "name": f.job_id,
            "kind": "job",
        })
    if f.step_name:
        locations.append({
            "name": f.step_name,
            "kind": "step",
        })
    return locations


def report_sarif(findings: list[Finding]) -> str:
    """
    Format findings as a SARIF 2.1.0 JSON string.

    The output can be uploaded to GitHub Code Scanning via:
      gh code-scanning upload-results --sarif results.sarif

    Or in a GitHub Actions workflow:
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

    Args:
        findings: List of Finding objects to report.

    Returns:
        A SARIF 2.1.0 JSON string.
    """
    sarif: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": _build_rules(findings),
                    }
                },
                "results": [_build_result(f) for f in findings],
            }
        ],
    }

    output = json.dumps(sarif, indent=2)
    logger.info("SARIF report: %d finding(s), %d bytes", len(findings), len(output))
    return output
