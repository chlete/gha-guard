# gha-guard

[![Tests](https://github.com/chlete/gha-guard/actions/workflows/python-app.yml/badge.svg)](https://github.com/chlete/gha-guard/actions/workflows/python-app.yml)

An AI-enhanced CLI tool that scans GitHub Actions workflow files for security vulnerabilities and provides actionable fix suggestions powered by Claude.

## Features

- **6 security rules** — detects unpinned actions, overly broad permissions, script injection, dangerous triggers, secrets in run blocks, and more
- **AI enrichment** — sends all findings to Claude in a single batched call for beginner-friendly explanations and concrete YAML fix suggestions
- **Multiple output formats** — console (colored), JSON, and SARIF 2.1.0
- **GitHub Code Scanning** — upload SARIF output to show findings as inline annotations on PR diffs, with precise line numbers
- **Pre-commit integration** — blocks commits that introduce new findings, automatically, before code leaves your machine
- **Config file** — `.gha-guard.yml` for per-repo severity thresholds, ignored rules, and excluded files; auto-discovered from the repo root
- **Severity filtering** — `--severity critical` to focus on what matters most
- **Structured logging** — `--log-file scan.log` for full debug traces; `--verbose` for console output
- **Type-safe** — fully annotated with mypy strict mode, zero type errors

## What it detects

| Rule | Severity | Description |
|---|---|---|
| `unpinned-action` | HIGH | Actions referenced by tag/branch instead of commit SHA |
| `write-all-permissions` | CRITICAL | Workflows with overly broad `write-all` permissions |
| `missing-permissions` | MEDIUM | Workflows without an explicit permissions block |
| `script-injection` | CRITICAL | User-controlled values used directly in `run:` blocks |
| `dangerous-trigger` | HIGH | Use of `pull_request_target` trigger |
| `manual-trigger` | LOW | Workflow can be triggered manually via `workflow_dispatch` |
| `secret-in-run` | HIGH | Secrets referenced directly in shell commands |

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Basic scan (rules only, no API key needed)

```bash
# Scan a directory of workflows
python3 -m src scan path/to/.github/workflows/

# Scan a single file
python3 -m src scan path/to/workflow.yml

# Output as JSON
python3 -m src scan path/to/.github/workflows/ --format json

# Output as SARIF (for GitHub Code Scanning)
python3 -m src scan path/to/.github/workflows/ --format sarif > results.sarif

# Only show critical findings
python3 -m src scan path/to/.github/workflows/ --severity critical

# Verbose logging
python3 -m src -v scan path/to/.github/workflows/

# Write full debug logs to a file
python3 -m src --log-file scan.log scan path/to/.github/workflows/

# Use an explicit config file
python3 -m src scan path/to/.github/workflows/ --config path/to/.gha-guard.yml
```

### AI-enhanced scan (requires Anthropic API key)

```bash
export ANTHROPIC_API_KEY=your-key-here
python3 -m src scan path/to/.github/workflows/ --enrich
```

The `--enrich` flag sends all findings to Claude in a single batched call, which returns:
- A beginner-friendly explanation of the risk
- A concrete YAML fix suggestion

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings — clean scan |
| `1` | Findings detected |
| `2` | Error (bad input, missing API key, etc.) |

## GitHub Code Scanning (SARIF)

Generate a SARIF file and upload it to GitHub Code Scanning so findings appear as annotations directly on the PR diff:

```yaml
# .github/workflows/security.yml
- name: Scan workflows
  run: python3 -m src scan .github/workflows/ --format sarif > results.sarif

- name: Upload to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Findings will appear in the **Security → Code scanning** tab and as inline annotations on pull requests.

## Pre-commit integration

Add gha-guard to your `.pre-commit-config.yaml` to run it automatically before every commit:

```yaml
repos:
  - repo: https://github.com/chlete/gha-guard
    rev: v0.1.0-alpha  # pin to a release tag
    hooks:
      - id: gha-guard
```

Then install the hook:

```bash
pip install pre-commit
pre-commit install
```

From now on, every `git commit` will scan your `.github/workflows/` files. The commit is blocked if any findings are detected (exit code 1).

To run manually against all files:

```bash
pre-commit run gha-guard --all-files
```

## Configuration

Create a `.gha-guard.yml` in your project root to customize behavior:

```yaml
# Minimum severity to report (critical, high, medium, low)
severity: high

# Rules to ignore (by rule ID)
ignore_rules:
  - unpinned-action
  - manual-trigger

# Workflow files to exclude (glob patterns)
exclude:
  - "**/test-*.yml"
  - ".github/workflows/legacy.yml"
```

CLI flags override config file values. You can also pass `--config path/to/.gha-guard.yml` explicitly.

## Project structure

```
src/
├── parser/          # Reads & normalizes workflow YAML into Python dataclasses
├── rules/           # Security checks (one file per rule)
├── llm/             # Claude integration for explanations & fixes
├── reporter/        # Output formatting (console, JSON, enriched)
├── config.py        # Configuration file loading
└── cli.py           # CLI entry point
tests/
├── fixtures/        # Example workflow files for testing
├── test_parser.py
├── test_rules.py
├── test_reporter.py
├── test_llm.py
├── test_cli.py
└── test_config.py
```
