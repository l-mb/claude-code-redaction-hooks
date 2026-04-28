# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Claude Code redaction hooks for preventing leakage of secrets and PII. Hooks filter prompts and tool inputs before execution.

## Build & Quality

```bash
uv sync                    # install dependencies
uv run ruff check .        # lint
uv run ruff format .       # format
uv run mypy .              # type check
uv run basedpyright .      # stricter type check
uv run pytest              # test
uv run pytest -k test_name # single test
```

## CLI Commands

```bash
redact hook                      # Run as Claude Code hook (reads JSON from stdin)
redact secret add --id ID        # Add hashed secret (reads from stdin or $REDACT_SECRET)
redact secret list               # List hashed rules
redact edit                      # Open rules in $EDITOR (validates after)
redact validate                  # Validate rules file syntax
redact check <file>...           # Scan files against rules
redact check --rules FILE        # Use custom rules file
redact check -q                  # Quiet mode (only output blocked)
redact claude-setup              # Configure Claude Code hooks (idempotent merge)
redact claude-setup --dry-run    # Print resulting settings.json without writing
redact claude-setup --uninstall  # Remove only the redact-hook entries
redact audit tail [-n N]         # Print last N audit entries (default 20)
redact audit since DURATION      # Print entries newer than e.g. 30m, 1h, 7d
```

Add `--global` to any command to use `~/.claude/.redaction_rules` instead of project.

## Architecture

```
src/redaction_hooks/
├── models.py    # Rule, Match, ScanResult dataclasses
├── config.py    # Load/save YAML rules, merge global+project
├── matcher.py   # PatternMatcher: regex, fixed string, hashed matching
├── actions.py   # apply_actions: block or redact with replacements
├── mappings.py  # Persistent original->replacement mappings (flock-locked, atomic save)
├── audit.py     # Append-only JSONL audit log of block/redact/warn outcomes
├── hooks.py     # Claude Code hook handlers (PreToolUse, PostToolUse, UserPromptSubmit)
└── cli.py       # Subcommand dispatcher
```

Mappings stored in `.claude/redaction_mappings.json` (project) or `~/.claude/redaction_mappings/global.json` (global).
Audit log at `.claude/redaction_audit.log` (project) or `~/.claude/redaction_audit.log` (global).

## Configuration

Rules in `.redaction_rules` (YAML):
- `id`: Rule identifier
- `pattern`: Regex (default) or fixed string (`is_regex: false`)
- `hashed`: If true, pattern is SHA-256 hash to compare against extracted segments
- `hash_extractor`: Regex to extract segments for hashing
- `action`: `block` or `redact`
- `replacement`: For redact - literal string, `ip`, `email`, or `hostname`
- `target`: `llm`, `tool`, or `both` (default)
- `tool`: Filter to specific tool name (e.g., `Bash`, `Write`), omit for all tools

See `.redaction_rules.example` for examples.
