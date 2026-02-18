"""Tests for the security rules."""

import os
import pytest

from src.parser import parse_workflow
from src.rules import run_all_rules, Severity
from src.parser.workflow_parser import Workflow, Job, Step, ActionRef


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_workflow(
    triggers=None,
    permissions=None,
    jobs=None,
    file_path="test.yml",
):
    """Build a minimal Workflow for testing individual rules."""
    return Workflow(
        file_path=file_path,
        name="Test",
        triggers=triggers or [],
        permissions=permissions,
        env={},
        jobs=jobs or [],
        raw={},
    )


def _make_job(job_id="test-job", steps=None, permissions=None):
    return Job(
        job_id=job_id,
        name=None,
        runs_on="ubuntu-latest",
        permissions=permissions,
        steps=steps or [],
        env={},
        raw={},
    )


def _make_step(name=None, uses=None, run=None, env=None):
    return Step(
        name=name,
        uses=uses,
        run=run,
        env=env or {},
        with_args={},
        raw={},
    )


def _find_by_rule(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# Integration: all rules against insecure fixture
# ---------------------------------------------------------------------------

class TestAllRulesIntegration:
    def test_detects_all_expected_rules(self, insecure_findings):
        rule_ids = {f.rule_id for f in insecure_findings}
        assert "unpinned-action" in rule_ids
        assert "write-all-permissions" in rule_ids
        assert "script-injection" in rule_ids
        assert "dangerous-trigger" in rule_ids
        assert "secret-in-run" in rule_ids

    def test_total_finding_count(self, insecure_findings):
        assert len(insecure_findings) == 7

    def test_secure_workflow_has_no_findings(self):
        secure = os.path.join(
            os.path.dirname(__file__),
            "fixtures/.github/workflows/secure-example.yml",
        )
        wf = parse_workflow(secure)
        findings = run_all_rules(wf)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Unpinned actions rule
# ---------------------------------------------------------------------------

class TestUnpinnedActions:
    def test_detects_tag_ref(self):
        step = _make_step(uses=ActionRef("actions/checkout@v3", "actions", "checkout", "v3", False))
        wf = _make_workflow(jobs=[_make_job(steps=[step])])
        findings = _find_by_rule(run_all_rules(wf), "unpinned-action")
        assert len(findings) == 1

    def test_ignores_pinned_sha(self):
        sha = "af513c7a016048ae468971c52ed77d9562c7c819"
        step = _make_step(uses=ActionRef(f"actions/checkout@{sha}", "actions", "checkout", sha, True))
        wf = _make_workflow(jobs=[_make_job(steps=[step])])
        findings = _find_by_rule(run_all_rules(wf), "unpinned-action")
        assert len(findings) == 0

    def test_ignores_run_steps(self):
        step = _make_step(run="echo hello")
        wf = _make_workflow(jobs=[_make_job(steps=[step])])
        findings = _find_by_rule(run_all_rules(wf), "unpinned-action")
        assert len(findings) == 0

    def test_counts_multiple_unpinned(self, insecure_findings):
        findings = _find_by_rule(insecure_findings, "unpinned-action")
        assert len(findings) == 3


# ---------------------------------------------------------------------------
# Permissions rule
# ---------------------------------------------------------------------------

class TestPermissions:
    def test_detects_write_all(self):
        wf = _make_workflow(permissions={"_all": "write-all"})
        findings = _find_by_rule(run_all_rules(wf), "write-all-permissions")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_detects_missing_permissions(self):
        wf = _make_workflow(permissions=None)
        findings = _find_by_rule(run_all_rules(wf), "missing-permissions")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_no_finding_for_scoped_permissions(self):
        wf = _make_workflow(permissions={"contents": "read"})
        perm_findings = [
            f for f in run_all_rules(wf)
            if f.rule_id in ("write-all-permissions", "missing-permissions")
        ]
        assert len(perm_findings) == 0

    def test_detects_job_level_write_all(self):
        job = _make_job(permissions={"_all": "write-all"})
        wf = _make_workflow(permissions={"contents": "read"}, jobs=[job])
        findings = _find_by_rule(run_all_rules(wf), "write-all-permissions")
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# Script injection rule
# ---------------------------------------------------------------------------

class TestScriptInjection:
    def test_detects_pr_title_injection(self):
        step = _make_step(run='echo "${{ github.event.pull_request.title }}"')
        wf = _make_workflow(jobs=[_make_job(steps=[step])])
        findings = _find_by_rule(run_all_rules(wf), "script-injection")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_detects_issue_body_injection(self):
        step = _make_step(run='echo "${{ github.event.issue.body }}"')
        wf = _make_workflow(jobs=[_make_job(steps=[step])])
        findings = _find_by_rule(run_all_rules(wf), "script-injection")
        assert len(findings) == 1

    def test_ignores_safe_contexts(self):
        step = _make_step(run='echo "${{ github.sha }}"')
        wf = _make_workflow(jobs=[_make_job(steps=[step])])
        findings = _find_by_rule(run_all_rules(wf), "script-injection")
        assert len(findings) == 0

    def test_ignores_steps_without_run(self):
        step = _make_step(uses=ActionRef("actions/checkout@v3", "actions", "checkout", "v3", False))
        wf = _make_workflow(jobs=[_make_job(steps=[step])])
        findings = _find_by_rule(run_all_rules(wf), "script-injection")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Dangerous triggers rule
# ---------------------------------------------------------------------------

class TestDangerousTriggers:
    def test_detects_pull_request_target(self):
        wf = _make_workflow(triggers=["pull_request_target"])
        findings = _find_by_rule(run_all_rules(wf), "dangerous-trigger")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_ignores_pull_request(self):
        wf = _make_workflow(triggers=["pull_request"])
        findings = _find_by_rule(run_all_rules(wf), "dangerous-trigger")
        assert len(findings) == 0

    def test_detects_workflow_dispatch(self):
        wf = _make_workflow(triggers=["workflow_dispatch"])
        findings = _find_by_rule(run_all_rules(wf), "manual-trigger")
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW


# ---------------------------------------------------------------------------
# Secret handling rule
# ---------------------------------------------------------------------------

class TestSecretHandling:
    def test_detects_secret_in_run(self):
        step = _make_step(run='curl -H "Authorization: Bearer ${{ secrets.TOKEN }}"')
        wf = _make_workflow(jobs=[_make_job(steps=[step])])
        findings = _find_by_rule(run_all_rules(wf), "secret-in-run")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_ignores_secret_in_env(self):
        step = _make_step(
            run='echo "$MY_TOKEN"',
            env={"MY_TOKEN": "${{ secrets.TOKEN }}"},
        )
        wf = _make_workflow(jobs=[_make_job(steps=[step])])
        findings = _find_by_rule(run_all_rules(wf), "secret-in-run")
        assert len(findings) == 0

    def test_detects_multiple_secrets(self):
        step = _make_step(run='echo ${{ secrets.A }} ${{ secrets.B }}')
        wf = _make_workflow(jobs=[_make_job(steps=[step])])
        findings = _find_by_rule(run_all_rules(wf), "secret-in-run")
        assert len(findings) == 1  # one finding per step, not per secret

    def test_ignores_steps_without_run(self):
        step = _make_step(uses=ActionRef("actions/checkout@v3", "actions", "checkout", "v3", False))
        wf = _make_workflow(jobs=[_make_job(steps=[step])])
        findings = _find_by_rule(run_all_rules(wf), "secret-in-run")
        assert len(findings) == 0
