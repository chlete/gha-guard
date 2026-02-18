"""
Configuration file support for gha-guard.

Looks for a .gha-guard.yml file in the project root and loads settings
that control which rules to run, severity thresholds, and file exclusions.

Example .gha-guard.yml:

    # Minimum severity to report (critical, high, medium, low)
    severity: high

    # Rules to ignore (by rule ID)
    ignore_rules:
      - unpinned-action
      - manual-trigger

    # Workflow files to exclude (glob patterns relative to scan path)
    exclude:
      - "**/test-*.yml"
      - ".github/workflows/legacy.yml"
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_FILENAME = ".gha-guard.yml"


@dataclass
class Config:
    """Parsed gha-guard configuration."""
    severity: str = "low"
    ignore_rules: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)


def load_config(config_path: Optional[str] = None, scan_path: Optional[str] = None) -> Config:
    """
    Load configuration from a .gha-guard.yml file.

    Search order:
      1. Explicit config_path if provided
      2. .gha-guard.yml in the scan_path directory (or its parent if scan_path is a file)
      3. .gha-guard.yml in the current working directory

    Returns a Config with defaults if no config file is found.
    """
    path = _find_config_file(config_path, scan_path)

    if path is None:
        logger.debug("No config file found, using defaults")
        return Config()

    logger.info("Loading config from %s", path)

    with open(path, "r") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        logger.warning("Config file is not a YAML mapping, using defaults")
        return Config()

    return Config(
        severity=raw.get("severity", "low"),
        ignore_rules=raw.get("ignore_rules", []),
        exclude=raw.get("exclude", []),
    )


def _find_config_file(
    config_path: Optional[str] = None,
    scan_path: Optional[str] = None,
) -> Optional[str]:
    """Find the config file, returning its path or None."""
    # 1. Explicit path
    if config_path:
        p = Path(config_path)
        if p.is_file():
            return str(p)
        logger.warning("Config file not found: %s", config_path)
        return None

    # 2. Relative to scan path
    if scan_path:
        scan_p = Path(scan_path)
        if scan_p.is_file():
            scan_p = scan_p.parent
        candidate = scan_p / DEFAULT_CONFIG_FILENAME
        if candidate.is_file():
            return str(candidate)
        # Walk up to find it (e.g. scan_path is .github/workflows/)
        for parent in scan_p.parents:
            candidate = parent / DEFAULT_CONFIG_FILENAME
            if candidate.is_file():
                return str(candidate)

    # 3. Current working directory
    cwd_candidate = Path.cwd() / DEFAULT_CONFIG_FILENAME
    if cwd_candidate.is_file():
        return str(cwd_candidate)

    return None
