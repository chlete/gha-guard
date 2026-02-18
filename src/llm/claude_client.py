"""
Claude LLM client: enriches security findings with explanations and fix suggestions.

Takes the deterministic findings from our rule engine and sends them to
Claude along with the original workflow YAML, asking for:
  1. A beginner-friendly explanation of the risk
  2. A concrete YAML fix
"""

import json
import logging
import os
from dataclasses import dataclass
from typing import Optional

from anthropic import Anthropic

from src.rules.engine import Finding

logger = logging.getLogger(__name__)


@dataclass
class EnrichedFinding:
    """A finding enriched with LLM-generated explanation and fix."""
    finding: Finding
    explanation: str    # beginner-friendly risk explanation
    suggested_fix: str  # concrete YAML snippet to fix the issue


SYSTEM_PROMPT = """You are a GitHub Actions security expert. You will receive:
1. A security finding (rule ID, severity, title, description, location)
2. The original workflow YAML file

For each finding, respond with EXACTLY this JSON format (no markdown, no extra text):
{
  "explanation": "A clear, beginner-friendly explanation of why this is a security risk. Use 2-3 sentences. Assume the reader knows basic GitHub Actions but not security.",
  "suggested_fix": "A concrete YAML snippet showing how to fix this specific issue. Only show the relevant part that needs to change, not the whole file."
}"""


def _build_user_prompt(finding: Finding, workflow_yaml: str) -> str:
    """Build the prompt for a single finding."""
    return f"""Here is the security finding:

Rule ID: {finding.rule_id}
Severity: {finding.severity.value}
Title: {finding.title}
Description: {finding.description}
File: {finding.file_path}
Job: {finding.job_id or "(workflow-level)"}
Step: {finding.step_name or "N/A"}

Here is the full workflow YAML:

```yaml
{workflow_yaml}
```

Respond with the JSON object only."""


def enrich_findings(
    findings: list[Finding],
    workflow_yaml: str,
    api_key: Optional[str] = None,
    model: str = "claude-sonnet-4-20250514",
) -> list[EnrichedFinding]:
    """
    Enrich a list of findings using Claude.

    Args:
        findings: The deterministic findings from the rule engine.
        workflow_yaml: The original workflow YAML content.
        api_key: Anthropic API key. Falls back to ANTHROPIC_API_KEY env var.
        model: Claude model to use.

    Returns:
        A list of EnrichedFinding objects with explanations and fixes.
    """
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise ValueError(
            "No Anthropic API key provided. Set ANTHROPIC_API_KEY environment "
            "variable or pass api_key parameter."
        )

    client = Anthropic(api_key=key)
    enriched = []

    for finding in findings:
        logger.info("Enriching finding: %s (%s)", finding.rule_id, finding.title)
        user_prompt = _build_user_prompt(finding, workflow_yaml)

        response = client.messages.create(
            model=model,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": user_prompt},
            ],
        )

        # Parse the JSON response
        response_text = response.content[0].text.strip()
        try:
            data = json.loads(response_text)
            explanation = data.get("explanation", "No explanation provided.")
            suggested_fix = data.get("suggested_fix", "No fix suggested.")
        except json.JSONDecodeError:
            logger.warning("Failed to parse Claude response as JSON for finding '%s'", finding.rule_id)
            # If Claude doesn't return valid JSON, use the raw text
            explanation = response_text
            suggested_fix = "Could not parse fix suggestion."

        enriched.append(EnrichedFinding(
            finding=finding,
            explanation=explanation,
            suggested_fix=suggested_fix,
        ))

    return enriched
