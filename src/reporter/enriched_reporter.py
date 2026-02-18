"""
Enriched console reporter: prints findings with LLM-generated explanations and fixes.
"""

import logging

from src.rules.engine import Severity
from src.llm.claude_client import EnrichedFinding

logger = logging.getLogger(__name__)


# ANSI color codes
COLORS = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH:     "\033[31m",
    Severity.MEDIUM:   "\033[33m",
    Severity.LOW:      "\033[36m",
}
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
RESET = "\033[0m"


def _severity_badge(severity: Severity) -> str:
    color = COLORS.get(severity, "")
    label = severity.value.upper()
    return f"{color}{BOLD}[{label:8s}]{RESET}"


def report_enriched(enriched_findings: list[EnrichedFinding], file_path: str = "") -> str:
    """
    Format enriched findings as a colored console report with
    LLM explanations and suggested fixes.
    """
    lines = []

    lines.append("")
    lines.append(f"{BOLD}{'=' * 60}{RESET}")
    lines.append(f"{BOLD}  GitHub Actions Security Report (AI-Enhanced){RESET}")
    if file_path:
        lines.append(f"  File: {file_path}")
    lines.append(f"{BOLD}{'=' * 60}{RESET}")
    lines.append("")

    if not enriched_findings:
        lines.append(f"  ✅ No security issues found!")
        lines.append("")
        report = "\n".join(lines)
        logger.info("Enriched report: no findings")
        print(report)
        return report

    # Summary
    counts: dict[Severity, int] = {}
    for ef in enriched_findings:
        sev = ef.finding.severity
        counts[sev] = counts.get(sev, 0) + 1

    lines.append(f"  Found {BOLD}{len(enriched_findings)}{RESET} issue(s):")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        if sev in counts:
            lines.append(f"    {_severity_badge(sev)} × {counts[sev]}")
    lines.append("")

    # Individual findings
    for i, ef in enumerate(enriched_findings, 1):
        f = ef.finding
        lines.append(f"  {'-' * 56}")
        lines.append(f"")
        lines.append(f"  {_severity_badge(f.severity)} #{i}: {BOLD}{f.title}{RESET}")
        lines.append(f"    Rule:  {f.rule_id}")
        if f.job_id:
            lines.append(f"    Job:   {f.job_id}")
        if f.step_name:
            lines.append(f"    Step:  {f.step_name}")

        # LLM explanation
        lines.append(f"")
        lines.append(f"    {BOLD}Why this matters:{RESET}")
        for desc_line in ef.explanation.split("\n"):
            lines.append(f"    {desc_line}")

        # Suggested fix
        lines.append(f"")
        lines.append(f"    {GREEN}{BOLD}Suggested fix:{RESET}")
        for fix_line in ef.suggested_fix.split("\n"):
            lines.append(f"    {GREEN}{fix_line}{RESET}")
        lines.append("")

    lines.append(f"  {'-' * 56}")
    lines.append(f"{BOLD}{'=' * 60}{RESET}")
    lines.append("")

    logger.info("Enriched report: %d finding(s) with AI explanations", len(enriched_findings))
    report = "\n".join(lines)
    print(report)
    return report
