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
    """Run as Claude Code hook."""
    return run_hook()


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


def cmd_claude_setup(args: argparse.Namespace) -> int:
    """Configure Claude Code hooks in settings.json."""
    if args.glob:
        settings_path = GLOBAL_RULES_DIR / "settings.json"
    else:
        settings_path = Path.cwd() / ".claude" / "settings.json"

    settings_path.parent.mkdir(parents=True, exist_ok=True)

    # Load existing settings
    if settings_path.exists():
        with settings_path.open() as f:
            settings = json.load(f)
    else:
        settings = {}

    # Add hooks configuration
    hooks_config = {
        "PreToolUse": [
            {
                "matcher": "Write|Edit|Bash",
                "hooks": [{"type": "command", "command": "redact hook"}],
            }
        ],
        "PostToolUse": [
            {
                "matcher": "Read|Bash|Grep|Glob|WebFetch",
                "hooks": [{"type": "command", "command": "redact hook"}],
            }
        ],
        "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "redact hook"}]}],
    }

    if "hooks" not in settings:
        settings["hooks"] = {}

    settings["hooks"].update(hooks_config)

    with settings_path.open("w") as f:
        json.dump(settings, f, indent=2)

    print(f"Updated {settings_path}", file=sys.stderr)
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

    parser.print_help()
    return 1
