"""
CLI entry point: ties together parser → rules → LLM → reporter.

Usage:
  # Basic scan (no LLM, just rules):
  python -m src.cli scan path/to/.github/workflows/

  # AI-enhanced scan (with Claude explanations):
  python -m src.cli scan path/to/.github/workflows/ --enrich

  # Output as JSON:
  python -m src.cli scan path/to/.github/workflows/ --format json

  # Scan a single file:
  python -m src.cli scan path/to/workflow.yml
"""

import os
import sys
import click

from src.parser import parse_workflow, parse_workflows_dir
from src.rules import run_all_rules
from src.reporter import report_console, report_json
from src.reporter.enriched_reporter import report_enriched


@click.group()
def cli():
    """GitHub Actions Security Scanner — find and fix CI/CD vulnerabilities."""
    pass


@cli.command()
@click.argument("path")
@click.option("--enrich", is_flag=True, help="Use Claude AI to explain findings and suggest fixes.")
@click.option("--format", "output_format", type=click.Choice(["console", "json"]), default="console", help="Output format.")
def scan(path: str, enrich: bool, output_format: str):
    """Scan GitHub Actions workflow files for security issues."""

    # Determine if path is a file or directory
    path = os.path.abspath(path)

    if os.path.isfile(path):
        workflows = [parse_workflow(path)]
    elif os.path.isdir(path):
        workflows = parse_workflows_dir(path)
    else:
        click.echo(f"Error: '{path}' is not a file or directory.", err=True)
        sys.exit(1)

    if not workflows:
        click.echo("No workflow files found.")
        return

    # Run rules on all workflows
    all_findings = []
    for wf in workflows:
        findings = run_all_rules(wf)
        all_findings.extend(findings)

    if not all_findings:
        click.echo("\n✅ No security issues found!")
        return

    # If --enrich, use Claude to add explanations
    if enrich:
        from src.llm import enrich_findings

        if not os.environ.get("ANTHROPIC_API_KEY"):
            click.echo(
                "Error: --enrich requires ANTHROPIC_API_KEY environment variable.",
                err=True,
            )
            sys.exit(1)

        # Read all workflow YAML content for context
        yaml_contents = {}
        for wf in workflows:
            with open(wf.file_path, "r") as f:
                yaml_contents[wf.file_path] = f.read()

        click.echo(f"Enriching {len(all_findings)} finding(s) with Claude AI...\n")

        enriched = []
        for finding in all_findings:
            yaml_content = yaml_contents.get(finding.file_path, "")
            result = enrich_findings([finding], yaml_content)
            enriched.extend(result)

        report_enriched(enriched, file_path=path)
    else:
        # Standard output
        if output_format == "json":
            output = report_json(all_findings)
            click.echo(output)
        else:
            report_console(all_findings, file_path=path)


if __name__ == "__main__":
    cli()
