"""
Rule: Detect risky secret handling patterns.

Secrets passed to environment variables of 'run:' steps that use
curl, wget, or other network tools could be leaked to external
services. Secrets should be handled carefully and never exposed
in logs or sent to untrusted endpoints.
"""

import re

from src.parser.workflow_parser import Workflow
from src.rules.engine import register_rule, Finding, Severity


SECRET_REF_PATTERN = re.compile(r"\$\{\{\s*secrets\.\w+\s*\}\}")


@register_rule
def check_secret_handling(workflow: Workflow) -> list[Finding]:
    findings = []
    for job in workflow.jobs:
        for step in job.steps:
            if not step.run:
                continue

            # Check if secrets are used directly in run blocks
            secrets_in_run = SECRET_REF_PATTERN.findall(step.run)
            if secrets_in_run:
                findings.append(Finding(
                    rule_id="secret-in-run",
                    severity=Severity.HIGH,
                    title="Secret used directly in 'run:' block",
                    description=(
                        f"The step uses {', '.join(secrets_in_run)} directly in a "
                        f"shell command. This risks exposing the secret in logs or "
                        f"to external processes. Pass secrets via environment variables "
                        f"instead:\n"
                        f"  env:\n"
                        f"    MY_SECRET: ${{{{ secrets.MY_SECRET }}}}\n"
                        f"  run: echo \"$MY_SECRET\""
                    ),
                    file_path=workflow.file_path,
                    job_id=job.job_id,
                    step_name=step.name or "(unnamed step)",
                    line_number=step.line_number,
                ))

    return findings
