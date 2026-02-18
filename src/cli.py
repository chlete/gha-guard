"""
CLI entry point: ties together parser → rules → LLM → reporter.

Usage:
  # Basic scan (no LLM, just rules):
  python3 -m src scan path/to/.github/workflows/

  # AI-enhanced scan (with Claude explanations):
  python3 -m src scan path/to/.github/workflows/ --enrich

  # Output as JSON:
  python3 -m src scan path/to/.github/workflows/ --format json

  # Scan a single file:
  python3 -m src scan path/to/workflow.yml

Exit codes:
  0 — no findings
  1 — findings detected
  2 — error (bad input, missing API key, etc.)
"""

import fnmatch
import logging
import os
import sys

import click
import yaml

from src.config import load_config
from src.parser import parse_workflow, parse_workflows_dir
from src.rules import run_all_rules, Severity
from src.reporter import report_console, report_json
from src.reporter.enriched_reporter import report_enriched

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _setup_logging(verbose: bool) -> None:
    """Configure logging based on verbosity flag."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose logging.")
def cli(verbose: bool):
    """GitHub Actions Security Scanner — find and fix CI/CD vulnerabilities."""
    _setup_logging(verbose)


@cli.command()
@click.argument("path")
@click.option("--enrich", is_flag=True, help="Use Claude AI to explain findings and suggest fixes.")
@click.option("--format", "output_format", type=click.Choice(["console", "json"]), default="console", help="Output format.")
@click.option("--severity", "min_severity", type=click.Choice(["critical", "high", "medium", "low"]), default=None, help="Minimum severity to report (overrides config file).")
@click.option("--config", "config_path", default=None, help="Path to .gha-guard.yml config file.")
def scan(path: str, enrich: bool, output_format: str, min_severity: str, config_path: str):
    """Scan GitHub Actions workflow files for security issues.

    Exits with code 0 if no issues found, 1 if issues found, 2 on error.
    """
    severity_order = {
        Severity.LOW: 0,
        Severity.MEDIUM: 1,
        Severity.HIGH: 2,
        Severity.CRITICAL: 3,
    }

    path = os.path.abspath(path)

    # Load config file (CLI flags override config values)
    config = load_config(config_path=config_path, scan_path=path)
    effective_severity = min_severity or config.severity
    min_sev = Severity(effective_severity)

    # Parse workflows
    try:
        if os.path.isfile(path):
            workflows = [parse_workflow(path)]
        elif os.path.isdir(path):
            workflows = parse_workflows_dir(path)
        else:
            click.echo(f"Error: '{path}' is not a file or directory.", err=True)
            sys.exit(EXIT_ERROR)
    except (yaml.YAMLError, ValueError) as e:
        click.echo(f"Error parsing workflow: {e}", err=True)
        sys.exit(EXIT_ERROR)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(EXIT_ERROR)

    if not workflows:
        click.echo("No workflow files found.")
        sys.exit(EXIT_OK)

    # Apply exclude patterns from config
    if config.exclude:
        before = len(workflows)
        workflows = [
            wf for wf in workflows
            if not any(fnmatch.fnmatch(wf.file_path, pat) for pat in config.exclude)
        ]
        excluded = before - len(workflows)
        if excluded:
            logger.info("Excluded %d workflow(s) via config", excluded)

    if not workflows:
        click.echo("All workflow files excluded by config.")
        sys.exit(EXIT_OK)

    # Run rules on all workflows
    all_findings = []
    for wf in workflows:
        findings = run_all_rules(wf)
        all_findings.extend(findings)

    # Filter by ignored rules from config
    if config.ignore_rules:
        before = len(all_findings)
        all_findings = [
            f for f in all_findings
            if f.rule_id not in config.ignore_rules
        ]
        ignored = before - len(all_findings)
        if ignored:
            logger.info("Ignored %d finding(s) via config ignore_rules", ignored)

    # Filter by minimum severity
    all_findings = [
        f for f in all_findings
        if severity_order[f.severity] >= severity_order[min_sev]
    ]

    if not all_findings:
        click.echo("\n✅ No security issues found!")
        sys.exit(EXIT_OK)

    # If --enrich, use Claude to add explanations
    if enrich:
        from src.llm import enrich_findings

        if not os.environ.get("ANTHROPIC_API_KEY"):
            click.echo(
                "Error: --enrich requires ANTHROPIC_API_KEY environment variable.",
                err=True,
            )
            sys.exit(EXIT_ERROR)

        # Read all workflow YAML content for context
        yaml_contents = {}
        for wf in workflows:
            try:
                with open(wf.file_path, "r") as f:
                    yaml_contents[wf.file_path] = f.read()
            except OSError as e:
                click.echo(f"Warning: could not read {wf.file_path}: {e}", err=True)

        click.echo(f"Enriching {len(all_findings)} finding(s) with Claude AI...\n")

        try:
            enriched = []
            for finding in all_findings:
                yaml_content = yaml_contents.get(finding.file_path, "")
                result = enrich_findings([finding], yaml_content)
                enriched.extend(result)
        except Exception as e:
            logger.error("Claude API error: %s", e)
            click.echo(f"Error calling Claude API: {e}", err=True)
            click.echo("Falling back to standard report.\n", err=True)
            report_console(all_findings, file_path=path)
            sys.exit(EXIT_FINDINGS)

        report_enriched(enriched, file_path=path)
    else:
        # Standard output
        if output_format == "json":
            output = report_json(all_findings)
            click.echo(output)
        else:
            report_console(all_findings, file_path=path)

    sys.exit(EXIT_FINDINGS)


if __name__ == "__main__":
    cli()
