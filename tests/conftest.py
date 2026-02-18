"""Shared fixtures for all tests."""

import os
import pytest

from src.parser import parse_workflow
from src.rules import run_all_rules


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures/.github/workflows")


@pytest.fixture
def insecure_workflow_path():
    """Path to the insecure example workflow fixture."""
    return os.path.join(FIXTURES_DIR, "insecure-example.yml")


@pytest.fixture
def insecure_workflow(insecure_workflow_path):
    """Parsed insecure example workflow."""
    return parse_workflow(insecure_workflow_path)


@pytest.fixture
def insecure_findings(insecure_workflow):
    """All findings from the insecure example workflow."""
    return run_all_rules(insecure_workflow)


@pytest.fixture
def fixtures_dir():
    """Path to the fixtures workflow directory."""
    return FIXTURES_DIR
