# Copyright 2025 Lars Marowsky-Brée <lars@marowsky-bree.eu>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Command-line interface for redaction hooks."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

from .actions import apply_actions
from .audit import parse_duration, prune_entries, read_entries
from .config import (
    GLOBAL_RULES_DIR,
    add_hashed_rule,
    get_rules_path,
    load_rules,
    load_rules_file,
)
from .hooks import run_hook
from .matcher import PatternMatcher


class _FileCheckResult:
    """Result of checking a single file."""

    __slots__ = ("blocked", "matched", "error", "messages")

    def __init__(self) -> None:
        self.blocked = False
        self.matched = False
        self.error = False
        self.messages: list[str] = []


def _check_single_file(file_path: Path, matcher: PatternMatcher, quiet: bool) -> _FileCheckResult:
    """Check a single file against rules, return result."""
    result = _FileCheckResult()

    if not file_path.exists():
        result.error = True
        result.messages.append(f"Error: File not found: {file_path}")
        return result

    try:
        content = file_path.read_text()
    except (OSError, UnicodeDecodeError):
        return result  # Skip binary/unreadable files

    matches = matcher.scan(content, "tool")
    if not matches:
        return result

    result.matched = True
    scan_result = apply_actions(content, matches, Path.cwd())

    if scan_result.block_reasons:
        result.blocked = True
        result.messages.append(f"{file_path}:")
        for reason in scan_result.block_reasons:
            result.messages.append(f"  BLOCKED: {reason}")
    elif not quiet:
        result.messages.append(f"{file_path}: {len(matches)} redaction match(es)")

    return result


def cmd_hook(args: argparse.Namespace) -> int:
    """Run as Claude Code hook.

    Uses `$CLAUDE_PROJECT_DIR` (set by Claude Code in the hook subprocess
    environment) when present so rules and the audit log are anchored to the
    project root rather than the hook process's cwd.
    """
    project_dir: Path | None = None
    env_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if env_dir:
        candidate = Path(env_dir).expanduser()
        if candidate.is_dir():
            project_dir = candidate
        else:
            sys.stderr.write(
                f"redaction_hooks: CLAUDE_PROJECT_DIR={env_dir!r} is not a directory; "
                "falling back to cwd\n"
            )
    return run_hook(project_dir)


def cmd_secret_add(args: argparse.Namespace) -> int:
    """Add a hashed secret rule."""
    secret = os.environ.get("REDACT_SECRET")
    if not secret:
        if sys.stdin.isatty():
            print("Enter secret (or set REDACT_SECRET env var):", file=sys.stderr)
        secret = sys.stdin.read().strip()

    if not secret:
        print("Error: No secret provided", file=sys.stderr)
        return 1

    rule = add_hashed_rule(
        secret=secret,
        rule_id=args.id,
        description=args.description or "",
        global_=args.glob,
    )
    path = get_rules_path(global_=args.glob)
    print(f"Added hashed rule '{rule.id}' to {path}", file=sys.stderr)
    return 0


def cmd_secret_list(args: argparse.Namespace) -> int:
    """List hashed rules."""
    path = get_rules_path(global_=args.glob)
    rules = load_rules_file(path)
    hashed = [r for r in rules if r.hashed]

    if not hashed:
        print(f"No hashed rules in {path}", file=sys.stderr)
        return 0

    for r in hashed:
        desc = f" - {r.description}" if r.description else ""
        print(f"{r.id}{desc}")
    return 0


def _run_validation(path: Path) -> int:
    """Run validation on a rules file, print errors, return exit code."""
    from .config import validate_rules_file

    errors = validate_rules_file(path)
    if errors:
        print(f"Validation errors in {path}:", file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        return 1
    print(f"{path}: OK")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate rules file syntax."""
    path = Path(args.rules) if args.rules else get_rules_path(global_=args.glob)
    return _run_validation(path)


def cmd_edit(args: argparse.Namespace) -> int:
    """Open rules file in editor."""
    path = get_rules_path(global_=args.glob)
    editor = os.environ.get("EDITOR", "vi")

    # Create file if it doesn't exist
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("rules: []\n")

    result = subprocess.call([editor, str(path)])
    if result != 0:
        return result

    return _run_validation(path)


def _get_check_exit_code(blocked: bool, error: bool, matched: bool, quiet: bool) -> int:
    """Determine exit code and print message if needed."""
    if blocked:
        return 2
    if error:
        return 1
    if not matched and not quiet:
        print("No matches found")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Scan file(s) against rules."""
    rules = load_rules_file(Path(args.rules)) if args.rules else load_rules()

    if not rules:
        if not args.quiet:
            print("No rules configured")
        return 0

    matcher = PatternMatcher(rules)
    any_blocked, any_matched, any_error = False, False, False

    for file_arg in args.files:
        result = _check_single_file(Path(file_arg), matcher, args.quiet)
        any_blocked |= result.blocked
        any_matched |= result.matched
        any_error |= result.error
        for msg in result.messages:
            print(msg, file=sys.stderr if result.error else sys.stdout)

    return _get_check_exit_code(any_blocked, any_error, any_matched, args.quiet)


def _audit_project_dir(global_: bool) -> Path | None:
    return None if global_ else Path.cwd()


def _print_entries(entries: list[dict[str, object]]) -> int:
    for entry in entries:
        print(json.dumps(entry, separators=(",", ":")))
    return 0


def cmd_audit_tail(args: argparse.Namespace) -> int:
    """Print the last N audit entries."""
    entries = read_entries(_audit_project_dir(args.glob))
    return _print_entries(entries[-args.lines :] if args.lines > 0 else entries)


def cmd_audit_since(args: argparse.Namespace) -> int:
    """Print audit entries newer than the given duration (e.g. '1h', '7d')."""
    from datetime import UTC, datetime, timedelta

    try:
        seconds = parse_duration(args.duration)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    cutoff = datetime.now(UTC) - timedelta(seconds=seconds)
    entries = []
    for entry in read_entries(_audit_project_dir(args.glob)):
        ts = entry.get("ts")
        if not isinstance(ts, str):
            continue
        try:
            entry_time = datetime.fromisoformat(ts)
        except ValueError:
            continue
        if entry_time >= cutoff:
            entries.append(entry)
    return _print_entries(entries)


def cmd_audit_prune(args: argparse.Namespace) -> int:
    """Delete audit entries older than the given duration (e.g. '30d')."""
    try:
        seconds = parse_duration(args.before)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    removed = prune_entries(seconds, _audit_project_dir(args.glob))
    print(f"Removed {removed} entries older than {args.before}", file=sys.stderr)
    return 0


def cmd_verify_cc_schema(args: argparse.Namespace) -> int:
    """Drive `claude -p` headlessly, capture every hook payload via
    REDACT_HOOK_DUMP_DIR, diff against the committed corpus, write reports.
    """
    from .verify_schema import run as run_verify

    return run_verify(
        report_dir=Path(args.report_dir),
        keep_tmp=args.keep_tmp,
        update_golden_flag=args.update_golden,
        claude_bin=args.claude,
    )


REDACT_HOOK_COMMAND = "redact hook"
# All entries fire for every tool (no `matcher`). The previous explicit lists
# missed Read, MultiEdit, WebSearch, Task/Agent, and MCP `mcp__*__*` tools,
# which silently bypassed `tool: Read`, `file_tools: read`, and similar rules.
# Per-rule `tool:` filters still scope individual rules.
_HOOK_EVENT_MATCHERS: dict[str, str | None] = {
    "PreToolUse": None,
    "PostToolUse": None,
    "PostToolUseFailure": None,
    "UserPromptSubmit": None,
    "PreCompact": None,  # both manual /compact and auto compaction
    "PostCompact": None,
    "InstructionsLoaded": None,
    "Stop": None,
    "SubagentStop": None,
}


def _entry_has_redact_hook(entry: dict[str, object]) -> bool:
    hooks = entry.get("hooks")
    if not isinstance(hooks, list):
        return False
    return any(isinstance(h, dict) and h.get("command") == REDACT_HOOK_COMMAND for h in hooks)


def _install_redact_hooks(settings: dict[str, object]) -> tuple[list[str], list[str]]:
    """Append redact-hook entries that aren't already present. Returns (added, skipped)."""
    hooks_section = settings.setdefault("hooks", {})
    if not isinstance(hooks_section, dict):
        raise ValueError("settings.hooks must be an object")
    added: list[str] = []
    skipped: list[str] = []
    for event, matcher in _HOOK_EVENT_MATCHERS.items():
        existing = hooks_section.setdefault(event, [])
        if not isinstance(existing, list):
            raise ValueError(f"settings.hooks.{event} must be a list")
        if any(_entry_has_redact_hook(e) for e in existing if isinstance(e, dict)):
            skipped.append(event)
            continue
        new_entry: dict[str, object] = {
            "hooks": [{"type": "command", "command": REDACT_HOOK_COMMAND}]
        }
        if matcher is not None:
            new_entry["matcher"] = matcher
        existing.append(new_entry)
        added.append(event)
    return added, skipped


def _uninstall_redact_hooks(settings: dict[str, object]) -> list[str]:
    """Remove only entries containing the redact-hook command. Returns events touched."""
    hooks_section = settings.get("hooks")
    if not isinstance(hooks_section, dict):
        return []
    changed: list[str] = []
    for event in list(hooks_section):
        entries = hooks_section[event]
        if not isinstance(entries, list):
            continue
        new_entries: list[dict[str, object]] = []
        modified = False
        for entry in entries:
            if not isinstance(entry, dict):
                new_entries.append(entry)
                continue
            hooks = entry.get("hooks")
            if not isinstance(hooks, list):
                new_entries.append(entry)
                continue
            kept = [
                h
                for h in hooks
                if not (isinstance(h, dict) and h.get("command") == REDACT_HOOK_COMMAND)
            ]
            if len(kept) == len(hooks):
                new_entries.append(entry)
                continue
            modified = True
            if kept:
                new_entry = dict(entry)
                new_entry["hooks"] = kept
                new_entries.append(new_entry)
        if modified:
            changed.append(event)
        if new_entries:
            hooks_section[event] = new_entries
        else:
            del hooks_section[event]
    return changed


def cmd_claude_setup(args: argparse.Namespace) -> int:
    """Configure Claude Code hooks in settings.json (or remove with --uninstall)."""
    settings_path = (
        GLOBAL_RULES_DIR / "settings.json"
        if args.glob
        else Path.cwd() / ".claude" / "settings.json"
    )

    if settings_path.exists():
        with settings_path.open() as f:
            settings = json.load(f)
        if not isinstance(settings, dict):
            print(f"Error: {settings_path} is not a JSON object", file=sys.stderr)
            return 1
    else:
        settings = {}

    if args.uninstall:
        changed = _uninstall_redact_hooks(settings)
        summary = (
            f"removed redact-hook from {changed}" if changed else "no redact-hook entries found"
        )
    else:
        added, skipped = _install_redact_hooks(settings)
        parts = []
        if added:
            parts.append(f"added to {added}")
        if skipped:
            parts.append(f"already present in {skipped}")
        summary = "; ".join(parts) if parts else "no changes"

    payload = json.dumps(settings, indent=2)
    if args.dry_run:
        print(payload)
        return 0

    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(payload + "\n")
    print(f"Updated {settings_path}: {summary}", file=sys.stderr)
    return 0


def main() -> int | NoReturn:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(prog="redact", description="Claude Code redaction hooks")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # hook subcommand
    subparsers.add_parser("hook", help="Run as Claude Code hook (reads JSON from stdin)")

    # secret subcommand group
    secret_parser = subparsers.add_parser("secret", help="Manage hashed secrets")
    secret_sub = secret_parser.add_subparsers(dest="secret_command", required=True)

    # secret add
    add_parser = secret_sub.add_parser("add", help="Add a hashed secret rule")
    add_parser.add_argument("--id", required=True, help="Rule ID")
    add_parser.add_argument("--description", help="Rule description")
    add_parser.add_argument(
        "--global", dest="glob", action="store_true", help="Add to global rules"
    )

    # secret list
    list_parser = secret_sub.add_parser("list", help="List hashed rules")
    list_parser.add_argument("--global", dest="glob", action="store_true", help="List global rules")

    # edit subcommand
    edit_parser = subparsers.add_parser("edit", help="Open rules file in $EDITOR")
    edit_parser.add_argument("--global", dest="glob", action="store_true", help="Edit global rules")

    # validate subcommand
    validate_parser = subparsers.add_parser("validate", help="Validate rules file syntax")
    validate_parser.add_argument("--global", dest="glob", action="store_true", help="Global rules")
    validate_parser.add_argument("--rules", help="Custom rules file")

    # check subcommand
    check_parser = subparsers.add_parser("check", help="Scan files against rules")
    check_parser.add_argument("files", nargs="+", help="Files to scan")
    check_parser.add_argument("--rules", help="Custom rules file")
    check_parser.add_argument("-q", "--quiet", action="store_true", help="Only output blocked")

    # claude-setup subcommand
    setup_parser = subparsers.add_parser("claude-setup", help="Configure Claude Code hooks")
    setup_parser.add_argument(
        "--global", dest="glob", action="store_true", help="Configure global settings"
    )
    setup_parser.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="Print the resulting settings.json without writing it",
    )
    setup_parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Remove only the redact-hook entries this tool added",
    )

    # audit subcommand group
    audit_parser = subparsers.add_parser("audit", help="Read the redaction audit log")
    audit_sub = audit_parser.add_subparsers(dest="audit_command", required=True)

    audit_tail = audit_sub.add_parser("tail", help="Print the last N audit entries")
    audit_tail.add_argument(
        "-n", "--lines", type=int, default=20, help="Number of entries (default 20; 0 = all)"
    )
    audit_tail.add_argument(
        "--global", dest="glob", action="store_true", help="Read the global audit log"
    )

    audit_since = audit_sub.add_parser(
        "since", help="Print entries newer than DURATION (e.g. 30m, 1h, 7d)"
    )
    audit_since.add_argument("duration", help="Duration (e.g. 30m, 1h, 7d, 1w)")
    audit_since.add_argument(
        "--global", dest="glob", action="store_true", help="Read the global audit log"
    )

    audit_prune = audit_sub.add_parser(
        "prune", help="Delete entries older than DURATION (e.g. 30d, 12w)"
    )
    audit_prune.add_argument(
        "--before", required=True, help="Delete entries older than this (e.g. 30d, 12w)"
    )
    audit_prune.add_argument(
        "--global", dest="glob", action="store_true", help="Prune the global audit log"
    )

    # verify-cc-schema subcommand
    verify_parser = subparsers.add_parser(
        "verify-cc-schema",
        help="Drive `claude -p` headlessly, capture hook payloads, diff against corpus",
    )
    verify_parser.add_argument(
        "--report-dir", default="./verify-report", help="Where to write report.json + report.md"
    )
    verify_parser.add_argument(
        "--keep-tmp", action="store_true", help="Keep the harness tmp project for inspection"
    )
    verify_parser.add_argument(
        "--update-golden",
        action="store_true",
        help="Refresh tests/fixtures/cc-payloads/ from this run's captures",
    )
    verify_parser.add_argument(
        "--claude", default="claude", help="Path to the claude binary (default: claude)"
    )

    args = parser.parse_args()

    if args.command == "hook":
        return cmd_hook(args)
    if args.command == "secret":
        if args.secret_command == "add":
            return cmd_secret_add(args)
        if args.secret_command == "list":
            return cmd_secret_list(args)
    if args.command == "edit":
        return cmd_edit(args)
    if args.command == "validate":
        return cmd_validate(args)
    if args.command == "check":
        return cmd_check(args)
    if args.command == "claude-setup":
        return cmd_claude_setup(args)
    if args.command == "audit":
        if args.audit_command == "tail":
            return cmd_audit_tail(args)
        if args.audit_command == "since":
            return cmd_audit_since(args)
        if args.audit_command == "prune":
            return cmd_audit_prune(args)
    if args.command == "verify-cc-schema":
        return cmd_verify_cc_schema(args)

    parser.print_help()
    return 1
