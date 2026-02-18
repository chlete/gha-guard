"""
Rule engine: defines the Finding model and runs all rules against a workflow.
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from src.parser.workflow_parser import Workflow

logger = logging.getLogger(__name__)


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Finding:
    """A single security finding produced by a rule."""
    rule_id: str          # e.g. "unpinned-action"
    severity: Severity
    title: str            # short summary
    description: str      # what was found
    file_path: str        # which workflow file
    job_id: str           # which job (empty string if workflow-level)
    step_name: str        # which step (empty string if job/workflow-level)


# Type alias: a rule is a function that takes a Workflow and returns findings
RuleFunc = Callable[[Workflow], list[Finding]]

# Registry of all rules
_rules: list[RuleFunc] = []


def register_rule(func: RuleFunc) -> RuleFunc:
    """Decorator to register a rule function."""
    _rules.append(func)
    return func


def run_all_rules(workflow: Workflow) -> list[Finding]:
    """Run every registered rule against a workflow and return all findings."""
    logger.info("Running %d rule(s) against %s", len(_rules), workflow.file_path)
    findings = []
    for rule in _rules:
        rule_findings = rule(workflow)
        findings.extend(rule_findings)
        if rule_findings:
            logger.debug("Rule '%s' produced %d finding(s)", rule.__name__, len(rule_findings))
    logger.info("Total: %d finding(s) for %s", len(findings), workflow.file_path)
    return findings
