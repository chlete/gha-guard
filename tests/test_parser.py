"""Tests for the workflow parser."""

import os
import pytest

from src.parser import parse_workflow, parse_workflows_dir
from src.parser.workflow_parser import (
    _parse_action_ref,
    _parse_triggers,
    _parse_permissions,
)


# ---------------------------------------------------------------------------
# _parse_action_ref
# ---------------------------------------------------------------------------

class TestParseActionRef:
    def test_standard_tag_ref(self):
        ref = _parse_action_ref("actions/checkout@v3")
        assert ref.owner == "actions"
        assert ref.repo == "checkout"
        assert ref.ref == "v3"
        assert ref.is_pinned is False

    def test_pinned_sha_ref(self):
        sha = "af513c7a016048ae468971c52ed77d9562c7c819"
        ref = _parse_action_ref(f"actions/checkout@{sha}")
        assert ref.is_pinned is True
        assert ref.ref == sha

    def test_branch_ref(self):
        ref = _parse_action_ref("some-org/deploy-action@main")
        assert ref.owner == "some-org"
        assert ref.repo == "deploy-action"
        assert ref.ref == "main"
        assert ref.is_pinned is False

    def test_docker_action_returns_none(self):
        assert _parse_action_ref("docker://alpine:3.8") is None

    def test_local_action_returns_none(self):
        assert _parse_action_ref("./.github/actions/my-action") is None

    def test_no_at_sign_returns_none(self):
        assert _parse_action_ref("actions/checkout") is None

    def test_no_slash_returns_none(self):
        assert _parse_action_ref("checkout@v3") is None

    def test_empty_string_returns_none(self):
        assert _parse_action_ref("") is None

    def test_subpath_action(self):
        ref = _parse_action_ref("actions/aws/s3-upload@v1")
        assert ref.owner == "actions"
        assert ref.repo == "aws"
        assert ref.ref == "v1"

    def test_almost_sha_not_pinned(self):
        """39 chars is not a valid SHA-1 — should not be pinned."""
        short = "a" * 39
        ref = _parse_action_ref(f"actions/checkout@{short}")
        assert ref.is_pinned is False

    def test_uppercase_sha_is_pinned(self):
        sha = "AF513C7A016048AE468971C52ED77D9562C7C819"
        ref = _parse_action_ref(f"actions/checkout@{sha}")
        assert ref.is_pinned is True


# ---------------------------------------------------------------------------
# _parse_triggers
# ---------------------------------------------------------------------------

class TestParseTriggers:
    def test_string_trigger(self):
        assert _parse_triggers("push") == ["push"]

    def test_list_trigger(self):
        assert _parse_triggers(["push", "pull_request"]) == ["push", "pull_request"]

    def test_dict_trigger(self):
        result = _parse_triggers({"push": {"branches": ["main"]}, "pull_request": None})
        assert "push" in result
        assert "pull_request" in result

    def test_none_returns_empty(self):
        assert _parse_triggers(None) == []


# ---------------------------------------------------------------------------
# _parse_permissions
# ---------------------------------------------------------------------------

class TestParsePermissions:
    def test_none_returns_none(self):
        assert _parse_permissions(None) is None

    def test_string_write_all(self):
        assert _parse_permissions("write-all") == {"_all": "write-all"}

    def test_string_read_all(self):
        assert _parse_permissions("read-all") == {"_all": "read-all"}

    def test_dict_passthrough(self):
        perms = {"contents": "read", "issues": "write"}
        assert _parse_permissions(perms) == perms


# ---------------------------------------------------------------------------
# parse_workflow (integration with fixture files)
# ---------------------------------------------------------------------------

class TestParseWorkflow:
    def test_metadata(self, insecure_workflow):
        assert insecure_workflow.name == "Insecure CI Example"
        assert "pull_request_target" in insecure_workflow.triggers
        assert "push" in insecure_workflow.triggers

    def test_permissions(self, insecure_workflow):
        assert insecure_workflow.permissions == {"_all": "write-all"}

    def test_job_count(self, insecure_workflow):
        assert len(insecure_workflow.jobs) == 2

    def test_build_job_steps(self, insecure_workflow):
        build = insecure_workflow.jobs[0]
        assert build.job_id == "build"
        assert len(build.steps) == 4

    def test_unpinned_action_detected(self, insecure_workflow):
        step = insecure_workflow.jobs[0].steps[0]
        assert step.uses is not None
        assert step.uses.is_pinned is False
        assert step.uses.ref == "v3"

    def test_pinned_action_detected(self, insecure_workflow):
        step = insecure_workflow.jobs[1].steps[0]
        assert step.uses.is_pinned is True

    def test_run_step_captured(self, insecure_workflow):
        step = insecure_workflow.jobs[0].steps[2]
        assert step.run is not None
        assert "${{" in step.run

    def test_step_env_captured(self, insecure_workflow):
        step = insecure_workflow.jobs[0].steps[3]
        assert "SECRET_KEY" in step.env

    def test_workflow_has_line_number(self, insecure_workflow):
        assert insecure_workflow.line_number is not None
        assert insecure_workflow.line_number >= 1

    def test_job_has_line_number(self, insecure_workflow):
        build = insecure_workflow.jobs[0]
        assert build.line_number is not None
        assert build.line_number >= 1

    def test_step_has_line_number(self, insecure_workflow):
        step = insecure_workflow.jobs[0].steps[0]
        assert step.line_number is not None
        assert step.line_number >= 1

    def test_step_line_numbers_are_ordered(self, insecure_workflow):
        steps = insecure_workflow.jobs[0].steps
        lines = [s.line_number for s in steps if s.line_number is not None]
        assert lines == sorted(lines)

    def test_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            parse_workflow(str(tmp_path / "nonexistent.yml"))

    def test_invalid_yaml(self, tmp_path):
        bad_file = tmp_path / "bad.yml"
        bad_file.write_text("just a string, not a mapping")
        with pytest.raises(ValueError):
            parse_workflow(str(bad_file))


# ---------------------------------------------------------------------------
# parse_workflows_dir
# ---------------------------------------------------------------------------

class TestParseWorkflowsDir:
    def test_finds_all_workflows(self, fixtures_dir):
        workflows = parse_workflows_dir(fixtures_dir)
        assert len(workflows) == 2  # insecure + secure

    def test_not_a_directory(self, tmp_path):
        fake = tmp_path / "not-a-dir"
        fake.write_text("hello")
        with pytest.raises(NotADirectoryError):
            parse_workflows_dir(str(fake))

    def test_empty_directory(self, tmp_path):
        workflows = parse_workflows_dir(str(tmp_path))
        assert workflows == []
