"""
Console reporter: prints findings to the terminal with colors and formatting.
"""

from src.rules.engine import Finding, Severity


# ANSI color codes for terminal output
COLORS = {
    Severity.CRITICAL: "\033[91m",  # bright red
    Severity.HIGH:     "\033[31m",  # red
    Severity.MEDIUM:   "\033[33m",  # yellow
    Severity.LOW:      "\033[36m",  # cyan
}
BOLD = "\033[1m"
RESET = "\033[0m"


def _severity_badge(severity: Severity) -> str:
    color = COLORS.get(severity, "")
    label = severity.value.upper()
    return f"{color}{BOLD}[{label:8s}]{RESET}"


def report_console(findings: list[Finding], file_path: str = "") -> str:
    """
    Format findings as a colored console report.

    Args:
        findings: List of Finding objects to report.
        file_path: Optional label for the report header.

    Returns:
        The formatted report string (also prints it).
    """
    lines = []

    # Header
    lines.append("")
    lines.append(f"{BOLD}{'=' * 60}{RESET}")
    lines.append(f"{BOLD}  GitHub Actions Security Report{RESET}")
    if file_path:
        lines.append(f"  File: {file_path}")
    lines.append(f"{BOLD}{'=' * 60}{RESET}")
    lines.append("")

    if not findings:
        lines.append(f"  ✅ No security issues found!")
        lines.append("")
        report = "\n".join(lines)
        print(report)
        return report

    # Summary counts
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines.append(f"  Found {BOLD}{len(findings)}{RESET} issue(s):")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        if sev in counts:
            lines.append(f"    {_severity_badge(sev)} × {counts[sev]}")
    lines.append("")
    lines.append(f"  {'-' * 56}")

    # Individual findings
    for i, f in enumerate(findings, 1):
        lines.append("")
        lines.append(f"  {_severity_badge(f.severity)} #{i}: {BOLD}{f.title}{RESET}")
        lines.append(f"    Rule:  {f.rule_id}")
        if f.job_id:
            lines.append(f"    Job:   {f.job_id}")
        if f.step_name:
            lines.append(f"    Step:  {f.step_name}")
        lines.append(f"")
        # Indent description
        for desc_line in f.description.split("\n"):
            lines.append(f"    {desc_line}")

    lines.append("")
    lines.append(f"{BOLD}{'=' * 60}{RESET}")
    lines.append("")

    report = "\n".join(lines)
    print(report)
    return report
