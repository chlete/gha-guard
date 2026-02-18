"""
Rule: Detect dangerous workflow triggers.

'pull_request_target' runs in the context of the base branch with
write permissions and access to secrets. If combined with checking
out the PR's head code, it allows untrusted code to run with
elevated privileges.
"""

from src.parser.workflow_parser import Workflow
from src.rules.engine import register_rule, Finding, Severity


@register_rule
def check_dangerous_triggers(workflow: Workflow) -> list[Finding]:
    findings = []

    if "pull_request_target" in workflow.triggers:
        findings.append(Finding(
            rule_id="dangerous-trigger",
            severity=Severity.HIGH,
            title="Workflow uses 'pull_request_target' trigger",
            description=(
                "The 'pull_request_target' trigger runs with write access to the "
                "base repository and has access to secrets. If this workflow checks "
                "out the PR head branch and runs any code from it, an attacker can "
                "submit a malicious PR that executes arbitrary code with elevated "
                "privileges. Consider using 'pull_request' instead, or ensure you "
                "never check out or execute untrusted PR code."
            ),
            file_path=workflow.file_path,
            job_id="",
            step_name="",
        ))

    if "workflow_dispatch" in workflow.triggers:
        # Not necessarily dangerous, but worth noting
        findings.append(Finding(
            rule_id="manual-trigger",
            severity=Severity.LOW,
            title="Workflow can be triggered manually",
            description=(
                "This workflow uses 'workflow_dispatch', allowing manual triggering. "
                "Ensure that only authorized users can trigger it and that inputs "
                "are validated."
            ),
            file_path=workflow.file_path,
            job_id="",
            step_name="",
        ))

    return findings
