# gha-guard

[![Tests](https://github.com/chlete/gha-guard/actions/workflows/python-app.yml/badge.svg)](https://github.com/chlete/gha-guard/actions/workflows/python-app.yml)

An AI-enhanced CLI tool that scans GitHub Actions workflow files for security vulnerabilities and provides actionable fix suggestions powered by Claude.

## What it detects

| Rule | Severity | Description |
|---|---|---|
| `unpinned-action` | HIGH | Actions referenced by tag/branch instead of commit SHA |
| `write-all-permissions` | CRITICAL | Workflows with overly broad `write-all` permissions |
| `missing-permissions` | MEDIUM | Workflows without an explicit permissions block |
| `script-injection` | CRITICAL | User-controlled values used directly in `run:` blocks |
| `dangerous-trigger` | HIGH | Use of `pull_request_target` trigger |
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

# Only show critical findings
python3 -m src scan path/to/.github/workflows/ --severity critical

# Verbose logging
python3 -m src -v scan path/to/.github/workflows/
```

### AI-enhanced scan (requires Anthropic API key)

```bash
export ANTHROPIC_API_KEY=your-key-here
python3 -m src scan path/to/.github/workflows/ --enrich
```

The `--enrich` flag sends each finding to Claude, which returns:
- A beginner-friendly explanation of the risk
- A concrete YAML fix suggestion

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings — clean scan |
| `1` | Findings detected |
| `2` | Error (bad input, missing API key, etc.) |

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
