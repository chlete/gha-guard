"""
Rule: Detect overly broad or missing permissions.

Workflows should follow the principle of least privilege.
Using 'write-all' or omitting permissions entirely grants
read-write access to all scopes, which is dangerous.
"""

from src.parser.workflow_parser import Workflow
from src.rules.engine import register_rule, Finding, Severity


@register_rule
def check_permissions(workflow: Workflow) -> list[Finding]:
    findings = []

    # Check workflow-level permissions
    if workflow.permissions is None:
        findings.append(Finding(
            rule_id="missing-permissions",
            severity=Severity.MEDIUM,
            title="No top-level permissions defined",
            description=(
                "This workflow does not declare a top-level 'permissions' block. "
                "Without it, the default token may have broad read-write access. "
                "Explicitly set permissions to the minimum required."
            ),
            file_path=workflow.file_path,
            job_id="",
            step_name="",
        ))
    elif workflow.permissions.get("_all") == "write-all":
        findings.append(Finding(
            rule_id="write-all-permissions",
            severity=Severity.CRITICAL,
            title="Workflow uses 'permissions: write-all'",
            description=(
                "This workflow grants write access to ALL scopes (contents, packages, "
                "issues, pull-requests, etc.). If any step is compromised, the attacker "
                "gets full write access to the repository."
            ),
            file_path=workflow.file_path,
            job_id="",
            step_name="",
        ))

    # Check job-level permissions
    for job in workflow.jobs:
        if job.permissions and job.permissions.get("_all") == "write-all":
            findings.append(Finding(
                rule_id="write-all-permissions",
                severity=Severity.CRITICAL,
                title=f"Job '{job.job_id}' uses 'permissions: write-all'",
                description=(
                    f"Job '{job.job_id}' grants write access to ALL scopes. "
                    f"Restrict permissions to only what this job needs."
                ),
                file_path=workflow.file_path,
                job_id=job.job_id,
                step_name="",
            ))

    return findings
