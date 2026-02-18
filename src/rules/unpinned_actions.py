"""
Rule: Detect unpinned GitHub Actions.

Actions referenced by tag (e.g. @v3) or branch (e.g. @main) can be
silently replaced by the action owner. Pinning to a full SHA ensures
you always run the exact code you reviewed.
"""

from src.parser.workflow_parser import Workflow
from src.rules.engine import register_rule, Finding, Severity


@register_rule
def check_unpinned_actions(workflow: Workflow) -> list[Finding]:
    findings = []
    for job in workflow.jobs:
        for step in job.steps:
            if step.uses and not step.uses.is_pinned:
                findings.append(Finding(
                    rule_id="unpinned-action",
                    severity=Severity.HIGH,
                    title="Unpinned action reference",
                    description=(
                        f"Action '{step.uses.full_ref}' is referenced by tag/branch "
                        f"'{step.uses.ref}', not by a commit SHA. A compromised or "
                        f"force-pushed tag could inject malicious code into your workflow."
                    ),
                    file_path=workflow.file_path,
                    job_id=job.job_id,
                    step_name=step.name or step.uses.full_ref,
                    line_number=step.line_number,
                ))
    return findings
