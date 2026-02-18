"""
Parser for GitHub Actions workflow files.

Reads .yml/.yaml files from a workflows directory and normalizes them
into a structured format that security rules can analyze.
"""

import logging
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Optional, Union

import yaml

logger = logging.getLogger(__name__)


class _LineLoader(yaml.SafeLoader):
    """PyYAML loader that stores the start line number on every mapping node."""


def _construct_mapping(loader: _LineLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    mapping: dict[Any, Any] = loader.construct_mapping(node, deep=True)
    mapping["__line__"] = node.start_mark.line + 1  # YAML lines are 0-indexed
    return mapping


_LineLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


@dataclass
class ActionRef:
    """A reference to a GitHub Action used in a step."""
    full_ref: str       # e.g. "actions/checkout@v3"
    owner: str          # e.g. "actions"
    repo: str           # e.g. "checkout"
    ref: str            # e.g. "v3" or a SHA
    is_pinned: bool     # True if ref is a full 40-char SHA


@dataclass
class Step:
    """A single step within a job."""
    name: Optional[str]
    uses: Optional[ActionRef]
    run: Optional[str]
    env: dict[str, str]
    with_args: dict[str, Any]
    raw: dict[str, Any]
    line_number: Optional[int] = None


@dataclass
class Job:
    """A single job within a workflow."""
    job_id: str
    name: Optional[str]
    runs_on: str
    permissions: Optional[dict[str, str]]
    steps: list[Step]
    env: dict[str, str]
    raw: dict[str, Any]
    line_number: Optional[int] = None


@dataclass
class Workflow:
    """A parsed GitHub Actions workflow."""
    file_path: str
    name: Optional[str]
    triggers: list[str]
    permissions: Optional[dict[str, str]]
    env: dict[str, str]
    jobs: list[Job]
    raw: dict[str, Any]
    line_number: Optional[int] = None


def _parse_action_ref(uses_string: str) -> Optional[ActionRef]:
    """Parse an action reference like 'actions/checkout@v3' into components."""
    if not uses_string or "/" not in uses_string:
        logger.debug("Skipping non-action uses reference: %s", uses_string)
        return None

    # Handle docker:// and ./ (local) actions
    if uses_string.startswith("docker://") or uses_string.startswith("./"):
        logger.debug("Skipping local/docker action: %s", uses_string)
        return None

    # Split owner/repo@ref
    if "@" not in uses_string:
        logger.debug("Skipping action without version ref: %s", uses_string)
        return None

    action_path, ref = uses_string.rsplit("@", 1)
    parts = action_path.split("/")
    if len(parts) < 2:
        return None

    owner = parts[0]
    repo = parts[1]

    # A full SHA-1 hash is 40 hex characters
    is_pinned = len(ref) == 40 and all(c in "0123456789abcdef" for c in ref.lower())
    logger.debug("Parsed action %s/%s@%s (pinned=%s)", owner, repo, ref[:12], is_pinned)

    return ActionRef(
        full_ref=uses_string,
        owner=owner,
        repo=repo,
        ref=ref,
        is_pinned=is_pinned,
    )


def _parse_step(step_raw: dict[str, Any]) -> Step:
    """Parse a raw step dictionary into a Step dataclass."""
    uses_str = step_raw.get("uses")
    return Step(
        name=step_raw.get("name"),
        uses=_parse_action_ref(uses_str) if uses_str else None,
        run=step_raw.get("run"),
        env=step_raw.get("env", {}),
        with_args=step_raw.get("with", {}),
        raw=step_raw,
        line_number=step_raw.get("__line__"),
    )


def _parse_triggers(on_field: Union[str, list[str], dict[str, Any], None]) -> list[str]:
    """Normalize the 'on' field into a list of trigger names."""
    if isinstance(on_field, str):
        return [on_field]
    elif isinstance(on_field, list):
        return on_field
    elif isinstance(on_field, dict):
        return list(on_field.keys())
    return []


def _parse_permissions(perm_field: Union[str, dict[str, str], None]) -> Optional[dict[str, str]]:
    """Normalize the permissions field into a dict or None."""
    if perm_field is None:
        return None
    if isinstance(perm_field, str):
        # e.g. "read-all" or "write-all"
        return {"_all": perm_field}
    if isinstance(perm_field, dict):
        return perm_field
    return None


def _parse_job(job_id: str, job_raw: dict[str, Any]) -> Job:
    """Parse a raw job dictionary into a Job dataclass."""
    steps_raw = [s for s in job_raw.get("steps", []) if isinstance(s, dict)]
    logger.debug("Parsing job '%s' with %d step(s)", job_id, len(steps_raw))
    return Job(
        job_id=job_id,
        name=job_raw.get("name"),
        runs_on=str(job_raw.get("runs-on", "")),
        permissions=_parse_permissions(job_raw.get("permissions")),
        steps=[_parse_step(s) for s in steps_raw],
        env=job_raw.get("env", {}),
        raw=job_raw,
        line_number=job_raw.get("__line__"),
    )


def parse_workflow(file_path: str) -> Workflow:
    """
    Parse a single GitHub Actions workflow YAML file.

    Args:
        file_path: Path to the .yml/.yaml workflow file.

    Returns:
        A Workflow dataclass with normalized data.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        yaml.YAMLError: If the file isn't valid YAML.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Workflow file not found: {file_path}")

    logger.info("Parsing workflow: %s", file_path)

    with open(path, "r") as f:
        raw = yaml.load(f, Loader=_LineLoader)  # noqa: S506  # _LineLoader is safe

    if not isinstance(raw, dict):
        logger.error("File is not a valid YAML mapping: %s", file_path)
        raise ValueError(f"Workflow file is not a valid YAML mapping: {file_path}")

    jobs_raw = raw.get("jobs", {})
    jobs = [
        _parse_job(job_id, job_data)
        for job_id, job_data in jobs_raw.items()
        if job_id != "__line__"
    ]
    triggers = _parse_triggers(raw.get("on", raw.get(True, [])))
    permissions = _parse_permissions(raw.get("permissions"))
    logger.debug(
        "Parsed '%s': %d job(s), triggers=%s, permissions=%s",
        raw.get("name", "(unnamed)"), len(jobs), triggers,
        "none" if permissions is None else list(permissions.keys()),
    )

    return Workflow(
        file_path=str(path),
        name=raw.get("name"),
        triggers=triggers,
        permissions=permissions,
        env=raw.get("env", {}),
        jobs=jobs,
        raw=raw,
        line_number=raw.get("__line__"),
    )


def parse_workflows_dir(dir_path: str) -> list[Workflow]:
    """
    Parse all workflow files in a directory.

    Args:
        dir_path: Path to a directory containing .yml/.yaml files
                  (typically .github/workflows/).

    Returns:
        A list of parsed Workflow objects.
    """
    path = Path(dir_path)
    if not path.is_dir():
        raise NotADirectoryError(f"Not a directory: {dir_path}")

    yaml_files = sorted(f for f in path.iterdir() if f.suffix in (".yml", ".yaml"))
    logger.debug("Found %d YAML file(s) in %s", len(yaml_files), dir_path)

    workflows = []
    for file in yaml_files:
        try:
            workflows.append(parse_workflow(str(file)))
        except (ValueError, yaml.YAMLError) as e:
            logger.warning("Skipping invalid workflow %s: %s", file.name, e)

    logger.info("Parsed %d workflow(s) from %s", len(workflows), dir_path)
    return workflows
