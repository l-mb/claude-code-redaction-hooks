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

"""Claude Code hook handlers."""

import json
import re
import sys
from pathlib import Path
from typing import Any

from .actions import apply_actions
from .audit import log_event
from .config import load_rules
from .matcher import PatternMatcher
from .models import Match, Rule
from .path_matcher import PathMatcher


def _audit(
    hook: str,
    action: str,
    matches: list[Match],
    *,
    tool: str | None = None,
    project_dir: Path | None = None,
) -> None:
    """Audit-log helper: extract rule IDs from matches and append a single entry."""
    rule_ids = sorted({m.rule.id for m in matches})
    if rule_ids:
        log_event(hook=hook, action=action, rule_ids=rule_ids, tool=tool, project_dir=project_dir)


# Regex to identify path-like tokens in shell commands (starts with ~, ., or /)
_PATH_PATTERN = re.compile(r"^[~./]")
_URL_PATTERN = re.compile(r"^https?://", re.IGNORECASE)
# Fallback regex for path extraction when shlex fails
_FALLBACK_PATH_RE = re.compile(r"(?:^|[\s;|&])([~/][^\s;|&]+|\.\.?/[^\s;|&]+)")
# Splits a compound shell command on ; && || | newline so each subcommand
# can be tokenized independently
_SHELL_SEPARATORS = re.compile(r"\s*(?:&&|\|\||;|\||\n)\s*")

# Tools that operate on files for file_tools filtering
_READ_TOOLS = {"Read"}
_WRITE_TOOLS = {"Write", "Edit", "MultiEdit"}
_FILE_TOOLS = _READ_TOOLS | _WRITE_TOOLS


def _extract_path_from_token(token: str) -> str | None:
    """Decide whether a single shell token contains a path; return the path or None."""
    if not token or _URL_PATTERN.match(token):
        return None
    if token.startswith("-"):
        # Flag with embedded value: --key=value or -k=value -- pull out the value
        if "=" in token:
            value = token.split("=", 1)[1]
            if (
                value
                and not _URL_PATTERN.match(value)
                and (_PATH_PATTERN.match(value) or "/" in value)
            ):
                return value
        return None
    if _PATH_PATTERN.match(token) or "/" in token:
        return token
    return None


def _extract_bash_paths(command: str) -> list[str]:
    """Extract path-like tokens from a shell command.

    Compound commands are split on `;`, `&&`, `||`, `|`, and newlines so each
    subcommand is tokenized independently. A token is a path if it starts with
    `/`, `./`, `../`, or `~`, or if it contains `/` and is not a flag.
    `--key=value` tokens contribute `value` (not the whole `--key=value`).
    """
    import shlex

    paths: list[str] = []
    for subcommand in _SHELL_SEPARATORS.split(command):
        if not subcommand.strip():
            continue
        try:
            tokens = shlex.split(subcommand)
        except ValueError:
            # Unclosed quotes etc -- fall back to a regex sweep over the original
            paths.extend(m.group(1) for m in _FALLBACK_PATH_RE.finditer(subcommand))
            continue
        for token in tokens:
            extracted = _extract_path_from_token(token)
            if extracted is not None:
                paths.append(extracted)
    return paths


def _get_tool_input_paths(tool_name: str, tool_input: dict[str, Any]) -> list[str]:
    """Extract file paths from tool input for path-based matching."""
    if tool_name in ("Read", "Write", "Edit", "MultiEdit"):
        path = tool_input.get("file_path")
        return [path] if path else []
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        return _extract_bash_paths(command)
    return []


def _emit_warnings(warn_reasons: list[str]) -> None:
    """Write warning messages to stderr."""
    for reason in warn_reasons:
        sys.stderr.write(f"Warning: {reason}\n")


def _read_file_head(
    path: str,
    project_dir: Path | None = None,
    lines: int = 100,
) -> tuple[str | None, str | None]:
    """Read first N lines of `path`, refusing reads outside `project_dir`.

    Symlinks are resolved before the boundary check so a symlink inside the
    project pointing at /etc/passwd is rejected. Returns (content, error):
    on success (text, None); on refusal/error (None, human-readable reason).
    """
    p = Path(path).expanduser()
    if not p.is_absolute():
        base = project_dir if project_dir is not None else Path.cwd()
        p = base / p
    try:
        resolved = p.resolve()
    except OSError as e:
        return None, f"cannot resolve path '{path}': {e}"
    if project_dir is not None:
        try:
            resolved.relative_to(project_dir.resolve())
        except ValueError:
            return None, f"path '{path}' resolves outside project boundary"
    try:
        with resolved.open(encoding="utf-8", errors="replace") as f:
            return "".join(line for _, line in zip(range(lines), f, strict=False)), None
    except (OSError, UnicodeDecodeError) as e:
        return None, f"cannot read '{path}': {e}"


def _file_tools_matches(file_tools: str | None, tool_name: str) -> bool:
    """Check if tool_name matches the file_tools filter."""
    if file_tools is None:
        return tool_name in _FILE_TOOLS
    if file_tools == "read":
        return tool_name in _READ_TOOLS
    if file_tools == "write":
        return tool_name in _WRITE_TOOLS
    if file_tools == "rw":
        return tool_name in _FILE_TOOLS
    return False


def _get_tool_input_content(tool_name: str, tool_input: dict[str, Any]) -> str | None:
    """Extract content to scan from tool input based on tool type."""
    if tool_name in ("Write", "Edit", "MultiEdit"):
        return tool_input.get("content") or tool_input.get("new_string")
    if tool_name == "Bash":
        return tool_input.get("command")
    if tool_name == "Read":
        return tool_input.get("file_path")
    return None


def _iter_output_fields(tool_name: str, tool_response: Any) -> list[tuple[str, str]]:
    """Return (field_path, content) pairs for each scannable string field in tool_response.

    Each field is scanned and redacted independently so the response shape required by
    `hookSpecificOutput.updatedToolOutput` is preserved. `field_path` is a dict key,
    or `matches[i]` for elements of a Grep/Glob matches list, or "" when the response
    itself is a string.
    """
    if not isinstance(tool_response, dict):
        text = str(tool_response) if tool_response else ""
        return [("", text)] if text else []

    if tool_name == "Bash":
        string_fields: tuple[str, ...] = ("stdout", "stderr", "output")
    elif tool_name in ("Read", "WebFetch"):
        string_fields = ("content", "output")
    elif tool_name in ("Grep", "Glob"):
        string_fields = ("output",)
    else:
        string_fields = ("content", "output", "result", "text")

    fields: list[tuple[str, str]] = []
    for key in string_fields:
        val = tool_response.get(key)
        if isinstance(val, str) and val:
            fields.append((key, val))

    if tool_name in ("Grep", "Glob"):
        matches_val = tool_response.get("matches")
        if isinstance(matches_val, list):
            for i, m in enumerate(matches_val):
                if isinstance(m, str) and m:
                    fields.append((f"matches[{i}]", m))

    return fields


def _set_output_field(tool_response: dict[str, Any], field_path: str, value: str) -> None:
    """Write `value` back to `tool_response` at `field_path` (set by _iter_output_fields)."""
    if "[" in field_path:
        key, idx_part = field_path.split("[", 1)
        tool_response[key][int(idx_part.rstrip("]"))] = value
    else:
        tool_response[field_path] = value


def _build_block_response(reasons: list[str]) -> dict[str, Any]:
    """Build a blocking response for PreToolUse."""
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "; ".join(reasons),
        },
        "continue": False,
        "stopReason": f"Blocked by redaction rules: {'; '.join(reasons)}",
    }


def _build_redact_response(
    original_input: dict[str, Any], redacted_content: str, tool_name: str
) -> dict[str, Any]:
    """Build a response with redacted content."""
    updated_input = dict(original_input)
    if tool_name in ("Write", "Edit", "MultiEdit"):
        if "content" in updated_input:
            updated_input["content"] = redacted_content
        elif "new_string" in updated_input:
            updated_input["new_string"] = redacted_content
    elif tool_name == "Bash":
        updated_input["command"] = redacted_content

    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": "Content redacted",
            "updatedInput": updated_input,
        },
        "continue": True,
        "systemMessage": "Content was redacted before execution",
    }


def _check_file_content_rules(
    rules: list[Rule],
    paths: list[str],
    tool_name: str,
    project_dir: Path | None = None,
) -> tuple[list[Match], list[str]]:
    """Check file_content_pattern rules against file contents.

    Paths that resolve outside `project_dir` always block, regardless of rule
    action -- a security tool should refuse to assess files outside its scope.
    Other unreadable cases preserve the older behavior: block only if a
    block-action rule could have applied.

    Returns (matches, block_reasons).
    """

    file_content_rules: list[Rule] = [
        r for r in rules if r.file_content_pattern and _file_tools_matches(r.file_tools, tool_name)
    ]
    if not file_content_rules or not paths:
        return [], []

    matches: list[Match] = []
    block_reasons: list[str] = []

    for path in paths:
        file_content, error = _read_file_head(path, project_dir)
        if file_content is None:
            is_outside = error is not None and "outside project boundary" in error
            if is_outside:
                ids = sorted({r.id for r in file_content_rules})
                block_reasons.append(f"file_content rule(s) {ids}: {error}")
                continue
            applicable = [r for r in file_content_rules if r.action == "block"]
            if applicable:
                block_reasons.append(
                    f"Cannot read file '{path}' for content check" + (f": {error}" if error else "")
                )
            continue

        for rule in file_content_rules:
            # If rule also has path_pattern, check path first
            if rule.path_pattern:
                pm = PathMatcher([rule], project_dir)
                if not pm.scan([path], "tool", tool_name):
                    continue

            # Match file_content_pattern against file content
            # rule.file_content_pattern is guaranteed non-None by filter above
            assert rule.file_content_pattern is not None
            compiled = re.compile(rule.file_content_pattern)
            m = compiled.search(file_content)
            if m:
                matches.append(
                    Match(
                        rule=rule,
                        start=m.start(),
                        end=m.end(),
                        text=m.group(0),
                    )
                )

    return matches, block_reasons


def handle_pre_tool_use(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle PreToolUse hook event."""
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    rules = load_rules(project_dir)
    if not rules:
        json.dump({"continue": True}, sys.stdout)
        return 0

    # Separate rules into categories (excluding file_content_pattern rules)
    path_only_rules = [
        r for r in rules if r.path_pattern and not r.pattern and not r.file_content_pattern
    ]
    content_only_rules = [
        r for r in rules if r.pattern and not r.path_pattern and not r.file_content_pattern
    ]
    combined_rules = [
        r for r in rules if r.path_pattern and r.pattern and not r.file_content_pattern
    ]

    all_matches: list[Match] = []
    paths = _get_tool_input_paths(tool_name, tool_input)
    content = _get_tool_input_content(tool_name, tool_input)

    # Check path-only rules
    if paths and path_only_rules:
        path_matcher = PathMatcher(path_only_rules, project_dir)
        all_matches.extend(path_matcher.scan(paths, "tool", tool_name))

    # Check content-only rules
    if content and content_only_rules:
        content_matcher = PatternMatcher(content_only_rules)
        all_matches.extend(content_matcher.scan(content, "tool", tool_name))

    # Check combined rules (both path AND content must match)
    if paths and content and combined_rules:
        path_matcher = PathMatcher(combined_rules, project_dir)
        path_matches = path_matcher.scan(paths, "tool", tool_name)
        matched_rule_ids = {m.rule.id for m in path_matches}
        # Only check content for rules where path already matched
        content_rules = [r for r in combined_rules if r.id in matched_rule_ids]
        if content_rules:
            content_matcher = PatternMatcher(content_rules)
            all_matches.extend(content_matcher.scan(content, "tool", tool_name))

    # Check file_content_pattern rules (reads actual file content)
    file_content_rules = [r for r in rules if r.file_content_pattern]
    if paths and file_content_rules:
        fc_matches, fc_block_reasons = _check_file_content_rules(
            file_content_rules, paths, tool_name, project_dir
        )
        all_matches.extend(fc_matches)
        # Immediately block if file was unreadable
        if fc_block_reasons:
            unreadable_ids = sorted({r.id for r in file_content_rules if r.action == "block"})
            log_event(
                hook="PreToolUse",
                action="block-unreadable",
                rule_ids=unreadable_ids,
                tool=tool_name,
                project_dir=project_dir,
            )
            json.dump(_build_block_response(fc_block_reasons), sys.stdout)
            sys.stderr.write(f"Blocked: {'; '.join(fc_block_reasons)}\n")
            return 2

    if not all_matches:
        json.dump({"continue": True}, sys.stdout)
        return 0

    result = apply_actions(content or "", all_matches, project_dir)

    # Emit warnings first
    if result.warn_reasons:
        _emit_warnings(result.warn_reasons)
    _audit(
        "PreToolUse",
        "warn",
        [m for m in all_matches if m.rule.action == "warn"],
        tool=tool_name,
        project_dir=project_dir,
    )

    if result.block_reasons:
        _audit(
            "PreToolUse",
            "block",
            [m for m in all_matches if m.rule.action == "block"],
            tool=tool_name,
            project_dir=project_dir,
        )
        json.dump(_build_block_response(result.block_reasons), sys.stdout)
        sys.stderr.write(f"Blocked: {'; '.join(result.block_reasons)}\n")
        return 2

    if content and result.redacted_text and result.redacted_text != content:
        _audit(
            "PreToolUse",
            "redact",
            [m for m in all_matches if m.rule.action == "redact"],
            tool=tool_name,
            project_dir=project_dir,
        )
        json.dump(_build_redact_response(tool_input, result.redacted_text, tool_name), sys.stdout)
        return 0

    json.dump({"continue": True}, sys.stdout)
    return 0


def handle_user_prompt_submit(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle UserPromptSubmit hook event."""
    prompt = data.get("prompt", "")
    if not prompt:
        json.dump({"continue": True}, sys.stdout)
        return 0

    rules = load_rules(project_dir)
    if not rules:
        json.dump({"continue": True}, sys.stdout)
        return 0

    matcher = PatternMatcher(rules)
    matches = matcher.scan(prompt, "llm")
    if not matches:
        json.dump({"continue": True}, sys.stdout)
        return 0

    result = apply_actions(prompt, matches, project_dir)

    # Emit warnings first
    if result.warn_reasons:
        _emit_warnings(result.warn_reasons)
    _audit(
        "UserPromptSubmit",
        "warn",
        [m for m in matches if m.rule.action == "warn"],
        project_dir=project_dir,
    )

    if result.block_reasons:
        _audit(
            "UserPromptSubmit",
            "block",
            [m for m in matches if m.rule.action == "block"],
            project_dir=project_dir,
        )
        response = {
            "decision": "block",
            "reason": f"Prompt blocked: {'; '.join(result.block_reasons)}",
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
            },
        }
        json.dump(response, sys.stdout)
        sys.stderr.write(f"Prompt blocked: {'; '.join(result.block_reasons)}\n")
        return 2

    # Warn about redact matches - UserPromptSubmit doesn't support updatedInput
    redact_matches = [m for m in matches if m.rule.action == "redact"]
    if redact_matches:
        ids = ", ".join(m.rule.id for m in redact_matches)
        sys.stderr.write(f"Warning: redact rules [{ids}] cannot modify prompts\n")
        _audit("UserPromptSubmit", "redact", redact_matches, project_dir=project_dir)

    json.dump({"continue": True}, sys.stdout)
    return 0


def handle_post_tool_use(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle PostToolUse hook event - scan tool output and apply block/redact actions.

    Redactions are written back to the original tool_response shape via
    hookSpecificOutput.updatedToolOutput (Claude Code v2.1.121+). For non-dict
    responses we cannot reliably reconstruct the schema, so redactions are skipped
    with a stderr warning.
    """
    tool_name = data.get("tool_name", "")
    tool_response = data.get("tool_response")

    rules = load_rules(project_dir)
    if not rules:
        json.dump({"continue": True}, sys.stdout)
        return 0

    fields = _iter_output_fields(tool_name, tool_response)
    if not fields:
        json.dump({"continue": True}, sys.stdout)
        return 0

    matcher = PatternMatcher(rules)
    block_reasons: list[str] = []
    warn_reasons: list[str] = []
    redacted_fields: list[tuple[str, str]] = []
    all_matches: list[Match] = []

    for field_path, content in fields:
        matches = matcher.scan(content, "tool", tool_name)
        if not matches:
            continue
        all_matches.extend(matches)
        result = apply_actions(content, matches, project_dir)
        block_reasons.extend(result.block_reasons)
        warn_reasons.extend(result.warn_reasons)
        if result.redacted_text is not None and result.redacted_text != content:
            redacted_fields.append((field_path, result.redacted_text))

    if warn_reasons:
        _emit_warnings(warn_reasons)
    _audit(
        "PostToolUse",
        "warn",
        [m for m in all_matches if m.rule.action == "warn"],
        tool=tool_name,
        project_dir=project_dir,
    )

    if block_reasons:
        _audit(
            "PostToolUse",
            "block",
            [m for m in all_matches if m.rule.action == "block"],
            tool=tool_name,
            project_dir=project_dir,
        )
        response = {
            "decision": "block",
            "reason": f"Tool output blocked: {'; '.join(block_reasons)}",
            "hookSpecificOutput": {"hookEventName": "PostToolUse"},
        }
        json.dump(response, sys.stdout)
        sys.stderr.write(f"Tool output blocked: {'; '.join(block_reasons)}\n")
        return 2

    redact_matches = [m for m in all_matches if m.rule.action == "redact"]

    if not redacted_fields:
        # Redact rules may have matched but produced no text change (e.g. mapping
        # collision producing same string), or there were no redact matches at all.
        if redact_matches:
            _audit("PostToolUse", "redact", redact_matches, tool=tool_name, project_dir=project_dir)
        json.dump({"continue": True}, sys.stdout)
        return 0

    if not isinstance(tool_response, dict):
        sys.stderr.write(f"Warning: cannot redact non-dict tool_response for {tool_name}\n")
        _audit("PostToolUse", "redact", redact_matches, tool=tool_name, project_dir=project_dir)
        json.dump({"continue": True}, sys.stdout)
        return 0

    for field_path, redacted in redacted_fields:
        _set_output_field(tool_response, field_path, redacted)

    _audit("PostToolUse", "redact", redact_matches, tool=tool_name, project_dir=project_dir)
    response = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": tool_response,
        },
        "systemMessage": "Tool output was redacted before being shown to the model",
    }
    json.dump(response, sys.stdout)
    return 0


def run_hook(project_dir: Path | None = None) -> int:
    """Main hook entry point. Reads JSON from stdin, dispatches to handler."""
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"Invalid JSON input: {e}\n")
        return 1

    event = data.get("hook_event_name", "")

    if event == "PreToolUse":
        return handle_pre_tool_use(data, project_dir)
    if event == "PostToolUse":
        return handle_post_tool_use(data, project_dir)
    if event == "UserPromptSubmit":
        return handle_user_prompt_submit(data, project_dir)

    # Unknown or unsupported event, allow to continue
    json.dump({"continue": True}, sys.stdout)
    return 0
