# gha-guard — Learning Guide

This document explains the **why** behind every design decision in gha-guard. It's written so you can come back later and understand not just what the code does, but why it was built this way.

---

## Table of Contents

1. [The Problem We're Solving](#the-problem-were-solving)
2. [Architecture Overview](#architecture-overview)
3. [Why This Layered Design?](#why-this-layered-design)
4. [Step-by-Step Walkthrough](#step-by-step-walkthrough)
   - [Parser](#1-parser)
   - [Rules](#2-rules)
   - [Reporter](#3-reporter)
   - [LLM Layer](#4-llm-layer)
   - [CLI](#5-cli)
   - [Config](#6-config)
   - [Pre-commit Integration](#7-pre-commit-integration)
5. [Python Concepts Used](#python-concepts-used)
   - [Dataclasses](#dataclasses)
   - [Decorators and the Registry Pattern](#decorators-and-the-registry-pattern)
   - [Enums](#enums)
   - [Type Hints](#type-hints)
   - [Mocking in Tests](#mocking-in-tests)
6. [Software Engineering Decisions](#software-engineering-decisions)
   - [Rules vs LLM — Why Both?](#rules-vs-llm--why-both)
   - [Exit Codes](#exit-codes)
   - [Structured Logging](#structured-logging)
   - [Type Checking with mypy](#type-checking-with-mypy)
   - [Pre-commit Hooks](#pre-commit-hooks)
   - [Config File Auto-Discovery](#config-file-auto-discovery)
7. [Testing Philosophy](#testing-philosophy)

---

## The Problem We're Solving

GitHub Actions workflows are YAML files that define CI/CD pipelines. They're powerful but have a large attack surface. Common mistakes include:

- **Unpinned actions** — `uses: actions/checkout@v3` references a mutable tag. If someone compromises the action repo and moves the `v3` tag, your pipeline silently runs malicious code. Pinning to a full SHA (`@af513c7a...`) prevents this.

- **Overly broad permissions** — `permissions: write-all` gives the workflow token full access to your repo. If any step is compromised, the attacker can push code, create releases, etc.

- **Script injection** — Writing `${{ github.event.pull_request.title }}` directly in a `run:` block means an attacker can craft a PR title like `"; rm -rf /; echo "` and it gets executed as shell code.

- **Dangerous triggers** — `pull_request_target` runs with write access and secrets, even for PRs from forks. Combined with checking out PR code, this is a well-known attack vector.

- **Secrets in shell commands** — `curl -H "Authorization: ${{ secrets.TOKEN }}"` can leak the secret in logs or process lists.

These are real-world vulnerabilities that have been exploited in major open-source projects.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI (cli.py)                        │
│  Ties everything together. Handles args, errors, exit codes │
└──────────┬──────────────────────────────────────────────────┘
           │
           │ uses
           ▼
┌──────────────────┐    ┌──────────────────┐    ┌─────────────┐
│     Parser       │───▶│     Rules        │───▶│  Reporter   │
│  YAML → Python   │    │  Find problems   │    │  Format     │
│  objects         │    │  deterministic   │    │  output     │
└──────────────────┘    └────────┬─────────┘    └──────┬──────┘
                                 │                     │
                                 ▼                     ▼
                        ┌──────────────────┐    ┌─────────────┐
                        │   LLM (Claude)   │───▶│  Enriched   │
                        │   Explain & fix  │    │  Reporter   │
                        └──────────────────┘    └─────────────┘
```

Data flows left to right:
1. **Parser** reads YAML, produces clean Python objects
2. **Rules** inspect those objects, produce findings
3. **Reporter** formats findings for humans or machines
4. **LLM** (optional) enriches findings with explanations

Each layer only knows about the one before it. The reporter doesn't know about YAML. The rules don't know about output formatting. This is called **separation of concerns**.

---

## Why This Layered Design?

Imagine you wrote everything in one big function:

```python
def scan(path):
    yaml = open(path).read()
    data = parse(yaml)
    for job in data["jobs"]:
        for step in job["steps"]:
            if "uses" in step and "@" in step["uses"]:
                # check if pinned...
                # format output...
                # call Claude...
                print(f"Found issue: {step['uses']}")
```

This works for a prototype, but it becomes a nightmare to maintain:
- Want to add JSON output? You have to change the scanning logic.
- Want to add a new rule? You have to modify the same giant function.
- Want to test the parser without running rules? You can't.
- Want to skip the LLM call? You have to add if-statements everywhere.

By splitting into layers, each piece is:
- **Independently testable** — test the parser without rules, test rules without the reporter
- **Easy to extend** — add a new rule by creating one file, add a new output format by creating one file
- **Easy to understand** — each file has one job

---

## Step-by-Step Walkthrough

### 1. Parser

**Files:** `src/parser/workflow_parser.py`

**What it does:** Reads a `.yml` file and converts it into Python dataclasses.

**Why dataclasses?**

A GitHub Actions workflow is a nested structure: a workflow has jobs, jobs have steps, steps have actions. We need to represent this in Python.

We could use plain dictionaries:

```python
step = raw_yaml["jobs"]["build"]["steps"][0]
action = step["uses"]  # "actions/checkout@v3"
# Now manually parse "actions/checkout@v3" every time we need the parts...
```

Problems: no autocomplete, easy to typo keys, no structure, have to re-parse strings everywhere.

Instead, we define **dataclasses** — lightweight Python classes that hold structured data:

```python
@dataclass
class ActionRef:
    full_ref: str       # "actions/checkout@v3"
    owner: str          # "actions"
    repo: str           # "checkout"
    ref: str            # "v3"
    is_pinned: bool     # False
```

The `@dataclass` decorator auto-generates `__init__`, `__repr__`, and `__eq__` for you. You write each field once. Your editor gives you autocomplete. The rest of the code becomes clean:

```python
if step.uses and not step.uses.is_pinned:
    report("Unpinned action!")
```

Instead of:

```python
if "uses" in step and "@" in step["uses"]:
    parts = step["uses"].split("@")
    ref = parts[1]
    if len(ref) != 40 or not all(c in "0123456789abcdef" for c in ref):
        report("Unpinned action!")
```

**The hierarchy:**

```
Workflow          ← one per .yml file
├── triggers      ← ["push", "pull_request_target"]
├── permissions   ← {"_all": "write-all"} or {"contents": "read"}
└── jobs[]
    └── Job
        ├── permissions
        └── steps[]
            └── Step
                ├── uses → ActionRef (or None)
                └── run  → string (or None)
```

The parser is a **translator** between raw YAML (messy, untyped) and this clean structure. It runs once, and from that point on, nothing else touches raw YAML.

---

### 2. Rules

**Files:** `src/rules/engine.py`, `src/rules/unpinned_actions.py`, etc.

**What it does:** Each rule is a function that takes a `Workflow` and returns a list of `Finding` objects.

**The registry pattern:**

```python
_rules = []

def register_rule(func):
    _rules.append(func)
    return func

@register_rule
def check_unpinned_actions(workflow):
    ...
```

When Python imports the file, the `@register_rule` decorator runs and adds the function to the `_rules` list. Then `run_all_rules()` just loops through that list.

**Why this pattern?** Adding a new rule is just:
1. Create a new file in `src/rules/`
2. Write a function with `@register_rule`
3. Import it in `src/rules/__init__.py`

You never edit the engine. You never edit other rules. Each rule is completely independent.

**The Finding dataclass:**

```python
@dataclass
class Finding:
    rule_id: str       # "unpinned-action"
    severity: Severity # Severity.HIGH
    title: str         # "Unpinned action reference"
    description: str   # detailed explanation
    file_path: str     # which file
    job_id: str        # which job
    step_name: str     # which step
```

This is the "contract" between rules and reporters. Rules produce findings, reporters consume them. Neither needs to know about the other.

---

### 3. Reporter

**Files:** `src/reporter/console_reporter.py`, `json_reporter.py`, `enriched_reporter.py`

**What it does:** Takes a list of `Finding` objects and formats them for output.

Three formats:
- **Console** — colored terminal output with ANSI escape codes
- **JSON** — structured data for piping to other tools
- **Enriched** — console output with LLM explanations added

**Why three?** Different use cases:
- A human running the tool locally wants colored console output
- A CI pipeline wants JSON to parse programmatically
- A developer learning about security wants the enriched explanations

Each reporter is a pure function: `list[Finding] → string`. No side effects, easy to test.

---

### 4. LLM Layer

**Files:** `src/llm/claude_client.py`

**What it does:** Takes findings + the original YAML, sends them to Claude, and gets back explanations and fix suggestions.

**Why not just use Claude for everything?**

This is a key design decision. We use **rules for detection** and **Claude for explanation**:

| Task | Best tool | Why |
|---|---|---|
| "Is this a 40-char SHA?" | Code | Fast, exact, free, deterministic |
| "Explain why this matters" | LLM | Creative, contextual, nuanced |

Rules are:
- **Deterministic** — same input, same output, every time
- **Free** — no API calls
- **Fast** — milliseconds
- **Reliable** — zero false positives for well-defined checks

LLMs are:
- **Non-deterministic** — might miss things or hallucinate
- **Expensive** — costs money per call
- **Slow** — seconds per call
- **Great at reasoning** — can explain context, suggest fixes

By combining both, you get reliable detection with intelligent explanation.

**The prompt design:**

```python
SYSTEM_PROMPT = """You are a GitHub Actions security expert...
respond with EXACTLY this JSON format..."""
```

We ask for **JSON only** — no markdown, no extra text. This makes parsing reliable. If Claude returns invalid JSON (rare), we fall back to using the raw text.

Each finding gets its own API call. This keeps prompts focused and responses precise. Claude sees the specific finding + the full YAML for context.

---

### 5. CLI

**Files:** `src/cli.py`, `src/__main__.py`

**What it does:** The entry point that ties everything together.

**Why `click`?**

`click` is a Python library for building CLIs. It handles:
- Argument parsing (`scan path/to/workflows/`)
- Options (`--enrich`, `--format json`, `--severity critical`)
- Help text (auto-generated from docstrings)
- Error messages

You define commands with decorators:

```python
@cli.command()
@click.argument("path")
@click.option("--enrich", is_flag=True)
def scan(path, enrich):
    ...
```

**Why `__main__.py`?**

This file lets you run the package as a module:

```bash
python3 -m src scan ...
```

Python looks for `__main__.py` when you use `-m`. It just imports and calls `cli()`.

**Exit codes:**

| Code | Meaning |
|---|---|
| 0 | Clean — no findings |
| 1 | Findings detected |
| 2 | Error |

This is a Unix convention. CI tools check exit codes to decide if a step passed or failed. Exit 0 = success, anything else = failure. By exiting 1 when findings exist, you can use gha-guard as a pipeline gate:

```yaml
- name: Security scan
  run: python3 -m src scan .github/workflows/
  # Pipeline fails if any findings are detected (exit 1)
```

**Error handling:**

Instead of letting Python crash with a traceback:

```
Traceback (most recent call last):
  File "...", line 42, in ...
yaml.scanner.ScannerError: mapping values are not allowed here
```

We catch exceptions and show friendly messages:

```
Error parsing workflow: mapping values are not allowed here
```

This is important for a tool that non-Python-developers will use.

---

### 6. Config

**Files:** `src/config.py`

**What it does:** Loads a `.gha-guard.yml` file that lets users customize behavior without changing code.

**Why a config file?**

Without it, every customization requires CLI flags:

```bash
python3 -m src scan workflows/ --severity high  # have to remember every time
```

With a config file, you set it once:

```yaml
# .gha-guard.yml
severity: high
ignore_rules:
  - manual-trigger
```

And it applies automatically. The config file lives in the repo, so the whole team shares the same settings.

**Auto-discovery:**

The tool searches for `.gha-guard.yml` in:
1. Explicit `--config` path (if provided)
2. The scan directory, then its parents (walks up the tree)
3. Current working directory

This means you can put the config at the repo root and scan from any subdirectory — it'll still find it.

**CLI overrides config:**

If you have `severity: low` in the config but pass `--severity critical` on the command line, the CLI wins. This follows the principle of **least surprise** — explicit is better than implicit.

---

### 7. Pre-commit Integration

**File:** `.pre-commit-hooks.yaml`

**What it does:** Lets users plug gha-guard into the [pre-commit](https://pre-commit.com/) framework so it runs automatically before every `git commit`.

**Why this matters:**

Right now, a developer has to remember to run `gha-guard scan` manually. They won't. Security tools only work if they run automatically at the right moment — and the right moment is before code is committed, not after it's already in a PR.

Pre-commit is a widely adopted framework for this. Users add a `.pre-commit-config.yaml` to their repo:

```yaml
repos:
  - repo: https://github.com/chlete/gha-guard
    rev: v0.1.0-alpha
    hooks:
      - id: gha-guard
```

After `pre-commit install`, every `git commit` automatically runs gha-guard against the `.github/workflows/` files. If any findings are detected, the commit is **blocked** (exit code 1). The developer sees the findings and fixes them before the code ever leaves their machine.

**How `.pre-commit-hooks.yaml` works:**

This file is what the pre-commit framework reads from a hook repository. It declares:

```yaml
- id: gha-guard           # the hook ID users reference
  name: gha-guard         # display name in terminal output
  language: python        # pre-commit installs this as a Python package
  entry: gha-guard scan   # the command to run
  files: ^.github/workflows/.*\.(yml|yaml)$  # only run on workflow files
  pass_filenames: false   # scan the whole directory, not individual files
```

The `files` pattern means the hook only triggers when a `.github/workflows/` file is staged. If you're committing a Python file, gha-guard doesn't run at all — no unnecessary overhead.

`pass_filenames: false` is important: pre-commit normally passes the list of changed files as arguments to the command. We don't want that — we want to scan the whole workflows directory, not just the files being committed (a changed file might interact with an unchanged one).

**The shift-left principle:**

This is an example of "shift left" in security — moving checks earlier in the development process. The earlier you catch a problem, the cheaper it is to fix:

```
Developer's machine → PR review → CI → Production
     ↑ cheapest                              ↑ most expensive
```

A pre-commit hook catches issues at the cheapest possible point.

---

## Python Concepts Used

### Dataclasses

A `@dataclass` is a decorator that auto-generates boilerplate for classes that mainly hold data:

```python
from dataclasses import dataclass

@dataclass
class Point:
    x: float
    y: float
```

This is equivalent to writing:

```python
class Point:
    def __init__(self, x: float, y: float):
        self.x = x
        self.y = y

    def __repr__(self):
        return f"Point(x={self.x}, y={self.y})"

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y
```

You write each field **once** instead of three times. We use dataclasses for `ActionRef`, `Step`, `Job`, `Workflow`, `Finding`, `EnrichedFinding`, and `Config`.

### Decorators and the Registry Pattern

A decorator is a function that wraps another function:

```python
def register_rule(func):
    _rules.append(func)  # side effect: add to list
    return func           # return the original function unchanged

@register_rule
def check_unpinned_actions(workflow):
    ...
```

The `@register_rule` syntax is just shorthand for:

```python
def check_unpinned_actions(workflow):
    ...
check_unpinned_actions = register_rule(check_unpinned_actions)
```

When Python imports the file, it calls `register_rule`, which adds the function to `_rules`. Later, `run_all_rules()` loops through `_rules` and calls each one.

This is the **registry pattern** — a way to collect things (functions, classes, handlers) without a central list that you have to manually maintain.

### Enums

```python
from enum import Enum

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
```

An enum is a fixed set of named values. Instead of passing strings around (easy to typo: `"hgih"`), you use `Severity.HIGH`. Your editor catches mistakes at write-time, not runtime.

### Type Hints

```python
def parse_workflow(file_path: str) -> Workflow:
```

Type hints tell you (and your editor) what types a function expects and returns. They don't enforce anything at runtime — Python ignores them. But they:
- Give you autocomplete
- Help you understand code without reading the implementation
- Can be statically verified with `mypy` (see [Type Checking with mypy](#type-checking-with-mypy))

Some common patterns used in this codebase:

```python
from typing import Any, Optional, Union

# Optional: the value can be this type OR None
name: Optional[str]                  # same as Union[str, None]

# Generic containers: always specify the element type
steps: list[Step]
env: dict[str, str]
raw: dict[str, Any]                  # Any = "I don't know the type"

# Union: one of several types
def _parse_triggers(
    on_field: Union[str, list[str], dict[str, Any], None]
) -> list[str]: ...
```

`Any` is an escape hatch — it tells mypy "don't check this". We use it for `raw` YAML data because YAML can contain anything. Everywhere else we're precise.

### Mocking in Tests

The LLM tests need to work **without an API key** and **without network calls**. We use `unittest.mock` to fake Claude's responses:

```python
from unittest.mock import patch, MagicMock
from anthropic.types import TextBlock

@patch("src.llm.claude_client.Anthropic")
def test_returns_enriched_findings(self, mock_anthropic_cls):
    mock_client = MagicMock()
    mock_anthropic_cls.return_value = mock_client
    mock_client.messages.create.return_value = _mock_claude_response(
        "This is dangerous because...",
        "uses: actions/checkout@abc123...",
    )
    result = enrich_findings(findings, yaml, api_key="fake")
    # Works! Never hits the real API.
```

`@patch` replaces the real `Anthropic` class with a fake one for the duration of the test. `MagicMock` is a magic object that accepts any attribute access or method call and returns another mock.

**Why we use real `TextBlock` instances in mocks:**

The client code filters Claude's response content with:

```python
text_blocks = [b for b in response.content if isinstance(b, TextBlock)]
```

If we used a plain `MagicMock()` as the content block, `isinstance(mock, TextBlock)` returns `False` — the filter would produce an empty list and the test would silently get no text back. By constructing a real `TextBlock(type="text", text=...)`, the `isinstance` check passes correctly.

This is a general principle: **when production code uses `isinstance` checks, mocks must be real instances of the expected type**, not generic `MagicMock` objects.

---

## Software Engineering Decisions

### Rules vs LLM — Why Both?

See the [LLM Layer section](#4-llm-layer) for the full explanation. The short version:

> Use code for what code is good at (precise, deterministic checks). Use AI for what AI is good at (reasoning, explaining, suggesting).

### Exit Codes

Unix convention: 0 = success, non-zero = failure. We use three codes:
- **0** — clean scan (no findings)
- **1** — findings detected (the tool worked, but there are issues)
- **2** — error (the tool itself failed)

This distinction matters in CI. You might want to allow exit 1 (findings exist but you'll fix them later) while still failing on exit 2 (something is broken).

### Structured Logging

#### Why logging instead of print?

`print()` always outputs and goes to stdout (mixed with your actual output). `logging` gives you:
- **Levels** — DEBUG, INFO, WARNING, ERROR — so you can control what's shown
- **Namespacing** — each module gets its own logger (`logging.getLogger(__name__)`), so you can tell *where* a message came from
- **Multiple destinations** — console and file simultaneously, with different verbosity levels
- **Structured format** — timestamps, level names, module names are added automatically

#### How we set it up

Every module creates its own logger at the top:

```python
import logging
logger = logging.getLogger(__name__)
```

`__name__` is the module's dotted path (e.g. `src.parser.workflow_parser`). This means log messages automatically include which module produced them.

The CLI configures the root logger in `_setup_logging()`:

```python
def _setup_logging(verbose, log_file=None):
    root = logging.getLogger()
    root.handlers.clear()  # prevent handler accumulation
    root.setLevel(logging.DEBUG)

    # Console: only warnings unless -v
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.WARNING)
    root.addHandler(console)

    # File: always full DEBUG
    if log_file:
        fh = logging.FileHandler(log_file, mode="w")
        fh.setLevel(logging.DEBUG)
        root.addHandler(fh)
```

Key decisions:
- **Console goes to stderr**, not stdout. This keeps log messages separate from the actual scan output (important when piping JSON to another tool).
- **File handler is always DEBUG**. Even without `-v`, `--log-file scan.log` captures everything. This is invaluable for debugging — you can reproduce an issue and send the log file.
- **`root.handlers.clear()`** prevents a subtle bug: if `_setup_logging` is called multiple times (e.g. in tests), handlers accumulate and you get duplicate log lines.

#### What we log and why

| Module | Level | What | Why |
|---|---|---|---|
| Parser | DEBUG | Skipped actions (docker/local) | Understand why an action wasn't analyzed |
| Parser | DEBUG | Parsed action details + pin status | Verify the parser is interpreting refs correctly |
| Parser | INFO | Workflow summary (jobs, triggers, permissions) | Quick overview of what was parsed |
| Rules | DEBUG | Per-rule execution time | Spot slow rules, optimize if needed |
| Rules | INFO | Total findings + total time | Performance baseline |
| LLM | INFO | API response time + token usage | Monitor costs and latency |
| LLM | DEBUG | Prompt length, raw response preview | Debug when Claude returns unexpected output |
| LLM | WARNING | JSON parse failures with response snippet | Know exactly what went wrong without re-running |
| CLI | INFO | Effective config, filter counts | Understand why findings were included/excluded |

#### Log levels — when to use which

- **DEBUG** — detailed internal state. Only developers care. "Parsed action actions/checkout@v3 (pinned=False)"
- **INFO** — high-level progress. "Running 5 rule(s) against workflow.yml", "Completed: 7 finding(s) in 1.5ms"
- **WARNING** — something unexpected but recoverable. "Failed to parse Claude response as JSON"
- **ERROR** — something failed. "Claude API request failed"

The rule of thumb: if you'd want to see it when debugging a user's issue, it should be logged.

#### The `--log-file` option

```bash
# Clean console output + full debug log to file
python3 -m src --log-file scan.log scan .github/workflows/
```

This is a common pattern in CLI tools. The user sees clean output, but a full trace is available for debugging. The log file includes timestamps, so you can correlate events and measure performance.

### Type Checking with mypy

mypy is a **static analyser** — it reads your code without running it and checks that types are used consistently. We run it with `strict = true`, which enables all checks.

#### What strict mode catches

```python
# bare dict — mypy asks: dict of what?
raw: dict          # error: Missing type parameters for generic type "dict"
raw: dict[str, Any]  # correct

# implicit Optional — PEP 484 says this is ambiguous
def foo(x: str = None): ...          # error
def foo(x: Optional[str] = None): ... # correct

# missing return type
def cli(verbose: bool): ...          # error: missing return type annotation
def cli(verbose: bool) -> None: ...  # correct
```

#### The real bug mypy found

The most valuable fix wasn't a style issue — it was a **latent runtime bug** in the LLM client. This is worth understanding in depth because it illustrates exactly why static analysis matters.

##### The original code

```python
response_text = response.content[0].text.strip()
```

This looks completely reasonable. You call the API, you get a response, you grab the text. It worked in every test. It worked in every manual run. But it was a time bomb.

##### Why it was wrong: Union types in the Anthropic SDK

The Anthropic Python SDK types `response.content` as a list of a **Union type** — meaning each element can be one of many different classes:

```python
# Simplified version of what the SDK actually declares:
content: list[
    TextBlock |
    ThinkingBlock |
    RedactedThinkingBlock |
    ToolUseBlock |
    ServerToolUseBlock |
    WebSearchToolResultBlock |
    WebFetchToolResultBlock |
    CodeExecutionToolResultBlock |
    BashCodeExecutionToolResultBlock |
    TextEditorCodeExecutionToolResultBlock |
    ToolSearchToolResultBlock |
    ContainerUploadBlock
]
```

That's 12 possible types. **Only `TextBlock` has a `.text` attribute.** All the others don't.

So `response.content[0].text` is only safe if the first element happens to be a `TextBlock`. If Claude returns a `ThinkingBlock` first (which it does when you enable extended thinking), or a `ToolUseBlock` (if you configure tools), the line crashes:

```
AttributeError: 'ThinkingBlock' object has no attribute 'text'
```

##### Why tests didn't catch it

Our tests always mocked the response with a single `TextBlock`. In production, Claude almost always returns a single `TextBlock` for simple prompts. So the bug was invisible — until it wasn't.

This is the class of bug that only surfaces when:
- You upgrade the `anthropic` package and Claude starts returning new block types
- You change the model to one that uses extended thinking by default
- Anthropic changes their API behaviour for certain prompts

You'd get a crash in production with no warning, and it would be hard to reproduce locally.

##### What mypy reported

When we ran `mypy src/`, it flagged the line with 10 separate errors — one for each union member that lacks `.text`:

```
src/llm/claude_client.py:127: error: Item "ThinkingBlock" of "TextBlock | ThinkingBlock | ..." has no attribute "text"
src/llm/claude_client.py:127: error: Item "ToolUseBlock" of "TextBlock | ThinkingBlock | ..." has no attribute "text"
... (8 more)
```

mypy is saying: *"You're accessing `.text` on something that might not have it. I can prove, just by reading the type signatures, that this will crash in some cases."*

##### The fix

```python
from anthropic.types import TextBlock

# Filter to only the block types that have .text
text_blocks = [b for b in response.content if isinstance(b, TextBlock)]
response_text = text_blocks[0].text.strip() if text_blocks else ""
```

`isinstance(b, TextBlock)` narrows the type: after the filter, mypy knows every element in `text_blocks` is definitely a `TextBlock`, so `.text` is safe. The `if text_blocks else ""` handles the edge case where there are no text blocks at all.

##### The broader lesson

This bug pattern — **accessing an attribute on a union type without checking which variant you have** — is extremely common when working with external APIs. APIs evolve. New response types get added. Code written against the original API silently breaks.

Static analysis catches it because it reasons about *all possible values*, not just the ones you happened to test. Your tests only cover the paths you thought of. mypy covers the paths the type system can prove exist.

> **Rule of thumb:** whenever you call an external API and access attributes on the response, check what the SDK's type annotations actually say. If the return type is a Union, you must handle all variants.

#### `__all__` and explicit exports

mypy's `strict` mode also checks that imports come from explicitly exported names. Without `__all__`, mypy treats re-exports in `__init__.py` as implementation details, not public API:

```python
# src/parser/__init__.py — before
from .workflow_parser import parse_workflow, parse_workflows_dir
# mypy error: Module "src.parser" does not explicitly export "parse_workflow"

# after
from .workflow_parser import parse_workflow, parse_workflows_dir
__all__ = ["parse_workflow", "parse_workflows_dir"]  # now it's explicit
```

This is good practice regardless of mypy — `__all__` documents the intended public API of a package.

#### Running mypy

```bash
python3 -m mypy src/
# Success: no issues found in 19 source files
```

It's also in CI (`python-app.yml`) so every PR is checked automatically.

### Pre-commit Hooks

The `.pre-commit-hooks.yaml` file is a standard contract that the pre-commit framework reads. By adding it to the repo root, gha-guard becomes a first-class pre-commit hook that any project can adopt with two lines of config.

The key design choice is `pass_filenames: false`. Pre-commit normally passes staged filenames as arguments — useful for linters that check individual files. But gha-guard scans a directory holistically (a workflow might reference another workflow), so we always scan the full `.github/workflows/` directory regardless of which files were staged.

The `files` pattern (`^.github/workflows/.*\.(yml|yaml)$`) ensures the hook only activates when a workflow file is part of the commit. No workflow changes = hook skipped entirely.

### Config File Auto-Discovery

Walking up the directory tree to find the config is a pattern used by many tools (`.gitignore`, `.eslintrc`, `pyproject.toml`). It means you can:
- Put the config at the repo root
- Run the tool from any subdirectory
- It still finds the config

---

## Testing Philosophy

### Test structure

Each source module has a corresponding test file:

| Source | Tests |
|---|---|
| `src/parser/` | `tests/test_parser.py` |
| `src/rules/` | `tests/test_rules.py` |
| `src/reporter/` | `tests/test_reporter.py` |
| `src/llm/` | `tests/test_llm.py` |
| `src/cli.py` | `tests/test_cli.py` |
| `src/config.py` | `tests/test_config.py` |

### Types of tests

1. **Unit tests** — test one function in isolation. Example: `_parse_action_ref("actions/checkout@v3")` returns the right `ActionRef`.

2. **Integration tests** — test multiple components together. Example: parse a fixture file, run all rules, check that the expected findings are produced.

3. **Edge case tests** — test boundary conditions. Example: what happens with an empty string? A 39-character almost-SHA? An empty directory?

4. **Error tests** — test that errors are handled correctly. Example: `parse_workflow("nonexistent.yml")` raises `FileNotFoundError`.

### Fixtures

We have two workflow fixtures:
- `insecure-example.yml` — deliberately insecure, triggers all rules
- `secure-example.yml` — properly hardened, triggers zero rules

The insecure fixture is our "positive test" (should find issues). The secure fixture is our "negative test" (should find nothing). Both are equally important — you need to verify the tool doesn't produce false positives.

### Shared fixtures with conftest.py

`conftest.py` defines pytest fixtures that are shared across all test files:

```python
@pytest.fixture
def insecure_workflow():
    return parse_workflow("fixtures/.../insecure-example.yml")
```

Any test can use `insecure_workflow` as a parameter and pytest automatically provides it. This avoids duplicating setup code across test files.

### Mocking external dependencies

The LLM tests mock the Anthropic API so they:
- Run without an API key
- Run without network access
- Run in milliseconds (no real API calls)
- Are deterministic (same fake response every time)

This is critical for CI — your tests should never depend on external services.
