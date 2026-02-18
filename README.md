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
python -m src scan path/to/.github/workflows/

# Scan a single file
python -m src scan path/to/workflow.yml

# Output as JSON
python -m src scan path/to/.github/workflows/ --format json
```

### AI-enhanced scan (requires Anthropic API key)

```bash
export ANTHROPIC_API_KEY=your-key-here
python -m src scan path/to/.github/workflows/ --enrich
```

The `--enrich` flag sends each finding to Claude, which returns:
- A beginner-friendly explanation of the risk
- A concrete YAML fix suggestion

## Project structure

```
src/
├── parser/          # Reads & normalizes workflow YAML into Python dataclasses
├── rules/           # Security checks (one file per rule)
├── llm/             # Claude integration for explanations & fixes
├── reporter/        # Output formatting (console, JSON, enriched)
└── cli.py           # CLI entry point
tests/
├── fixtures/        # Example workflow files for testing
├── test_parser.py
├── test_rules.py
├── test_reporter.py
└── test_llm.py
```
