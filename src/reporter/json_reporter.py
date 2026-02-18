"""
JSON reporter: outputs findings as structured JSON for programmatic use.
"""

import json
import logging

from src.rules.engine import Finding

logger = logging.getLogger(__name__)


def report_json(findings: list[Finding]) -> str:
    """
    Format findings as a JSON string.

    Args:
        findings: List of Finding objects to report.

    Returns:
        A JSON string with all findings.
    """
    data = {
        "total": len(findings),
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "file_path": f.file_path,
                "job_id": f.job_id,
                "step_name": f.step_name,
                "line_number": f.line_number,
            }
            for f in findings
        ],
    }
    output = json.dumps(data, indent=2)
    logger.info("JSON report: %d finding(s), %d bytes", len(findings), len(output))
    return output
