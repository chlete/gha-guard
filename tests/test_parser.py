"""Tests for the workflow parser."""

import os
import sys

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.parser import parse_workflow, parse_workflows_dir


def test_parse_single_workflow():
    fixture = os.path.join(
        os.path.dirname(__file__),
        "fixtures/.github/workflows/insecure-example.yml",
    )
    wf = parse_workflow(fixture)

    # Basic metadata
    assert wf.name == "Insecure CI Example"
    assert "pull_request_target" in wf.triggers
    assert "push" in wf.triggers

    # Permissions
    assert wf.permissions == {"_all": "write-all"}

    # Jobs
    assert len(wf.jobs) == 2

    build_job = wf.jobs[0]
    assert build_job.job_id == "build"
    assert len(build_job.steps) == 4

    # Unpinned action check
    checkout_step = build_job.steps[0]
    assert checkout_step.uses is not None
    assert checkout_step.uses.owner == "actions"
    assert checkout_step.uses.repo == "checkout"
    assert checkout_step.uses.ref == "v3"
    assert checkout_step.uses.is_pinned is False

    # Script injection — the run field contains an expression
    greet_step = build_job.steps[2]
    assert "${{" in greet_step.run

    # Pinned action in deploy job
    deploy_job = wf.jobs[1]
    pinned_step = deploy_job.steps[0]
    assert pinned_step.uses.is_pinned is True

    # Unpinned (branch ref) action
    deploy_action_step = deploy_job.steps[1]
    assert deploy_action_step.uses.is_pinned is False
    assert deploy_action_step.uses.ref == "main"

    print("All assertions passed!")


def test_parse_workflows_dir():
    fixtures_dir = os.path.join(
        os.path.dirname(__file__),
        "fixtures/.github/workflows",
    )
    workflows = parse_workflows_dir(fixtures_dir)
    assert len(workflows) == 1
    assert workflows[0].name == "Insecure CI Example"
    print("Directory parsing passed!")


if __name__ == "__main__":
    test_parse_single_workflow()
    test_parse_workflows_dir()
    print("\n✓ All parser tests passed.")
