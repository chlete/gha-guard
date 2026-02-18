"""
Rule: Detect script injection via GitHub expression contexts.

When user-controlled values like github.event.issue.title or
github.event.pull_request.body are used directly in a 'run:' block,
an attacker can craft a malicious payload that executes as shell code.
"""

import re

from src.parser.workflow_parser import Workflow
from src.rules.engine import register_rule, Finding, Severity


# GitHub contexts that contain user-controlled input
DANGEROUS_CONTEXTS = [
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.pages.*.page_name",
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.head_commit.author.email",
    "github.head_ref",
]

# Regex to find ${{ ... }} expressions in run blocks
EXPRESSION_PATTERN = re.compile(r"\$\{\{.*?\}\}", re.DOTALL)


@register_rule
def check_script_injection(workflow: Workflow) -> list[Finding]:
    findings = []
    for job in workflow.jobs:
        for step in job.steps:
            if not step.run:
                continue

            # Find all expressions in the run block
            expressions = EXPRESSION_PATTERN.findall(step.run)
            for expr in expressions:
                expr_inner = expr.strip("${} ")
                for dangerous in DANGEROUS_CONTEXTS:
                    if dangerous in expr_inner:
                        findings.append(Finding(
                            rule_id="script-injection",
                            severity=Severity.CRITICAL,
                            title="Potential script injection",
                            description=(
                                f"The expression '{expr}' in a 'run:' block uses "
                                f"the user-controlled context '{dangerous}'. An attacker "
                                f"could craft a malicious value that executes arbitrary "
                                f"shell commands. Use an environment variable instead:\n"
                                f"  env:\n"
                                f"    SAFE_VALUE: {expr}\n"
                                f"  run: echo \"$SAFE_VALUE\""
                            ),
                            file_path=workflow.file_path,
                            job_id=job.job_id,
                            step_name=step.name or "(unnamed step)",
                            line_number=step.line_number,
                        ))
    return findings
