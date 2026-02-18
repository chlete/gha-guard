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
import time
from dataclasses import dataclass
from typing import Optional

from anthropic import Anthropic
from anthropic.types import TextBlock

from src.rules.engine import Finding

logger = logging.getLogger(__name__)


@dataclass
class EnrichedFinding:
    """A finding enriched with LLM-generated explanation and fix."""
    finding: Finding
    explanation: str    # beginner-friendly risk explanation
    suggested_fix: str  # concrete YAML snippet to fix the issue


SYSTEM_PROMPT = """You are a GitHub Actions security expert. You will receive:
1. A list of security findings (each with an index, rule ID, severity, title, description, location)
2. The original workflow YAML file

Respond with EXACTLY a JSON array — one object per finding, in the same order, no markdown, no extra text:
[
  {
    "explanation": "A clear, beginner-friendly explanation of why this is a security risk. Use 2-3 sentences. Assume the reader knows basic GitHub Actions but not security.",
    "suggested_fix": "A concrete YAML snippet showing how to fix this specific issue. Only show the relevant part that needs to change, not the whole file."
  }
]

The array must have exactly as many objects as there are findings, in the same order."""


def _build_user_prompt(findings: list[Finding], workflow_yaml: str) -> str:
    """Build a batched prompt for all findings in one request."""
    findings_text = ""
    for i, f in enumerate(findings, 1):
        findings_text += f"""Finding {i}:
  Rule ID: {f.rule_id}
  Severity: {f.severity.value}
  Title: {f.title}
  Description: {f.description}
  File: {f.file_path}
  Job: {f.job_id or "(workflow-level)"}
  Step: {f.step_name or "N/A"}

"""
    return f"""Here are {len(findings)} security finding(s):

{findings_text}Here is the full workflow YAML:

```yaml
{workflow_yaml}
```

Respond with the JSON array only."""


def enrich_findings(
    findings: list[Finding],
    workflow_yaml: str,
    api_key: Optional[str] = None,
    model: str = "claude-sonnet-4-20250514",
) -> list[EnrichedFinding]:
    """
    Enrich a list of findings using Claude in a single batched API call.

    All findings are sent together in one prompt, and Claude returns a JSON
    array with one object per finding. This is significantly cheaper and faster
    than one API call per finding.

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

    if not findings:
        return []

    logger.info(
        "Enriching %d finding(s) in a single batched call (model=%s)",
        len(findings), model,
    )
    client = Anthropic(api_key=key)
    user_prompt = _build_user_prompt(findings, workflow_yaml)
    logger.debug("Batched prompt length: %d chars", len(user_prompt))

    t0 = time.monotonic()
    try:
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": user_prompt},
            ],
        )
    except Exception as e:
        logger.error("Claude API request failed: %s", e)
        raise

    elapsed_ms = (time.monotonic() - t0) * 1000
    input_tokens = getattr(response.usage, "input_tokens", None)
    output_tokens = getattr(response.usage, "output_tokens", None)
    logger.info(
        "Claude response: %.0fms, tokens in=%s out=%s",
        elapsed_ms, input_tokens, output_tokens,
    )

    # Extract text — filter to TextBlock only (other block types lack .text)
    text_blocks = [b for b in response.content if isinstance(b, TextBlock)]
    response_text = text_blocks[0].text.strip() if text_blocks else ""
    logger.debug("Raw response (%d chars): %.200s", len(response_text), response_text)

    # Parse the JSON array response
    try:
        items = json.loads(response_text)
        if not isinstance(items, list) or len(items) != len(findings):
            raise ValueError(
                f"Expected a JSON array of {len(findings)} item(s), "
                f"got: {type(items).__name__} with "
                f"{len(items) if isinstance(items, list) else '?'} item(s)"
            )
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(
            "Failed to parse batched Claude response: %s. "
            "Response starts with: %.200s",
            e, response_text,
        )
        # Fallback: return raw text as explanation for all findings
        return [
            EnrichedFinding(
                finding=f,
                explanation=response_text,
                suggested_fix="Could not parse fix suggestion.",
            )
            for f in findings
        ]

    enriched = []
    for finding, item in zip(findings, items):
        enriched.append(EnrichedFinding(
            finding=finding,
            explanation=item.get("explanation", "No explanation provided."),
            suggested_fix=item.get("suggested_fix", "No fix suggested."),
        ))

    logger.info("Enrichment complete: %d finding(s) processed in 1 API call", len(enriched))
    return enriched
