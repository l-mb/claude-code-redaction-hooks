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
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .actions import apply_actions
from .audit import log_event
from .config import load_rules
from .matcher import DEFAULT_REGEX_TIMEOUT_SECONDS, PatternMatcher, RegexTimeoutError, regex_timeout
from .models import Match, Rule
from .path_matcher import PathMatcher


def _audit(
    hook: str,
    action: str,
    matches: list[Match],
    *,
    tool: str | None = None,
    tool_use_id: str | None = None,
    project_dir: Path | None = None,
) -> None:
    """Audit-log helper: extract rule IDs from matches and append a single entry."""
    rule_ids = sorted({m.rule.id for m in matches})
    if rule_ids:
        log_event(
            hook=hook,
            action=action,
            rule_ids=rule_ids,
            tool=tool,
            tool_use_id=tool_use_id,
            project_dir=project_dir,
        )


def _audit_timeouts(
    hook: str,
    rule_ids: list[str],
    *,
    tool: str | None = None,
    tool_use_id: str | None = None,
    project_dir: Path | None = None,
) -> None:
    """Audit any rules whose regex exceeded the timeout."""
    if rule_ids:
        log_event(
            hook=hook,
            action="regex_timeout",
            rule_ids=sorted(set(rule_ids)),
            tool=tool,
            tool_use_id=tool_use_id,
            project_dir=project_dir,
        )


def _audit_schema_drift_stale_extractor(
    hook: str,
    matches: list[Match],
    *,
    tool: str | None = None,
    tool_use_id: str | None = None,
    project_dir: Path | None = None,
) -> None:
    """Drift signal: per-tool extractor returned nothing but a recursive walk
    over the payload still found a rule match. The CC payload shape for this
    tool may have moved underneath us. Surfaces in audit + stderr; query with
    `redact audit since 30d | jq 'select(.action=="schema-drift")'`.
    """
    if not matches:
        return
    rule_ids = sorted({m.rule.id for m in matches})
    log_event(
        hook=hook,
        action="schema-drift",
        rule_ids=rule_ids,
        tool=tool,
        tool_use_id=tool_use_id,
        project_dir=project_dir,
    )
    sys.stderr.write(
        f"schema-drift: {hook}/{tool or '<n/a>'} matched only via recursive walk "
        f"(rules {rule_ids}); per-tool extractor may be stale\n"
    )


def _audit_schema_drift_missing_key(
    hook: str,
    key: str,
    *,
    project_dir: Path | None = None,
) -> None:
    """Drift signal: a handler couldn't proceed because a required top-level
    input key was missing/empty, even though configured rules WOULD have fired
    if it had been present. Uses a synthetic rule_id `missing-key:<key>` so
    operators can grep/filter cleanly.
    """
    sys.stderr.write(
        f"schema-drift: {hook} received payload missing required key '{key}'; handler skipped\n"
    )
    log_event(
        hook=hook,
        action="schema-drift",
        rule_ids=[f"missing-key:{key}"],
        project_dir=project_dir,
    )


# Regex to identify path-like tokens in shell commands (starts with ~, ., or /)
_PATH_PATTERN = re.compile(r"^[~./]")
_URL_PATTERN = re.compile(r"^https?://", re.IGNORECASE)
# Fallback regex for path extraction when shlex fails
_FALLBACK_PATH_RE = re.compile(r"(?:^|[\s;|&])([~/][^\s;|&]+|\.\.?/[^\s;|&]+)")
# Splits a compound shell command on ; && || | newline so each subcommand
# can be tokenized independently
_SHELL_SEPARATORS = re.compile(r"\s*(?:&&|\|\||;|\||\n)\s*")
# Shell binaries whose `-c <inner>` argument should be recursively re-tokenized.
# Without this, a path inside `bash -c "cat /etc/passwd"` arrives as the single
# shlex token `cat /etc/passwd`, which fnmatch then fails to match against
# `/etc/passwd` -- silently bypassing path-pattern rules. Matched on basename
# so `/usr/bin/bash` and `bash` are both recognised.
_SHELL_BINARIES = frozenset({"bash", "sh", "dash", "zsh", "ksh"})

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


def _shell_inner_command(tokens: list[str]) -> str | None:
    """If `tokens` is a `<shell> -c <inner>` invocation, return `<inner>`.

    Strips leading `VAR=value` assignments (e.g. `env FOO=1 bash -c ...`) and
    accepts both `-c <inner>` and `-c=<inner>`. Returns None if the leading
    binary is not a known shell or no `-c` argument is present.
    """
    i = 0
    while i < len(tokens) and "=" in tokens[i] and not tokens[i].startswith(("-", "/")):
        i += 1  # leading env-style VAR=value assignment
    if i >= len(tokens):
        return None
    if Path(tokens[i]).name not in _SHELL_BINARIES:
        return None
    for j in range(i + 1, len(tokens)):
        if tokens[j] == "-c" and j + 1 < len(tokens):
            return tokens[j + 1]
        if tokens[j].startswith("-c="):
            return tokens[j][3:]
    return None


def _extract_bash_paths(command: str) -> list[str]:
    """Extract path-like tokens from a shell command.

    Compound commands are split on `;`, `&&`, `||`, `|`, and newlines so each
    subcommand is tokenized independently. A token is a path if it starts with
    `/`, `./`, `../`, or `~`, or if it contains `/` and is not a flag.
    `--key=value` tokens contribute `value` (not the whole `--key=value`).
    Wrapped shells (`bash -c "<inner>"`, `sh -c '<inner>'`, etc.) are recursed
    into so paths inside the wrapped command are not missed.
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
        inner = _shell_inner_command(tokens)
        if inner is not None:
            paths.extend(_extract_bash_paths(inner))
        for token in tokens:
            extracted = _extract_path_from_token(token)
            if extracted is not None:
                paths.append(extracted)
    return paths


def _get_tool_input_paths(tool_name: str, tool_input: dict[str, Any]) -> list[str]:
    """Extract file paths from tool input for path-based matching.

    Per-tool keys verified against real CC 2.1.x payloads:
      - Read / Write / Edit / MultiEdit: tool_input.file_path
      - Bash: tool_input.command (parsed for path tokens)
      - Grep / Glob: tool_input.path (the directory under search)
    """
    if tool_name in ("Read", "Write", "Edit", "MultiEdit"):
        path = tool_input.get("file_path")
        return [path] if path else []
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        return _extract_bash_paths(command)
    if tool_name in ("Grep", "Glob"):
        path = tool_input.get("path")
        return [path] if path else []
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
    """Extract content to scan from tool input based on tool type.

    Per-tool keys verified against real CC 2.1.x payloads:
      - Write / Edit / MultiEdit: content or new_string
      - Bash: command
      - Read: file_path
      - Grep / Glob: pattern (the regex / glob expression itself)
      - ToolSearch: query (the deferred-tool discovery string)
      - Task / Agent: description + prompt joined (subagent gets both)
    """
    if tool_name in ("Write", "Edit", "MultiEdit"):
        content = tool_input.get("content") or tool_input.get("new_string")
        return content if isinstance(content, str) else None
    if tool_name == "Bash":
        command = tool_input.get("command")
        return command if isinstance(command, str) else None
    if tool_name == "Read":
        file_path = tool_input.get("file_path")
        return file_path if isinstance(file_path, str) else None
    if tool_name in ("Grep", "Glob"):
        pattern = tool_input.get("pattern")
        return pattern if isinstance(pattern, str) else None
    if tool_name == "ToolSearch":
        query = tool_input.get("query")
        return query if isinstance(query, str) else None
    if tool_name in ("Task", "Agent"):
        parts: list[str] = []
        for k in ("description", "prompt"):
            v = tool_input.get(k)
            if isinstance(v, str) and v:
                parts.append(v)
        return "\n".join(parts) if parts else None
    return None


def _get_nested(obj: Any, dotted: str) -> Any:
    """Walk `obj` along a dotted key path; return None if any step is missing."""
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _iter_output_fields(tool_name: str, tool_response: Any) -> list[tuple[str, str]]:
    """Return (field_path, content) pairs for each scannable string field in tool_response.

    Each field is scanned and redacted independently so the response shape required by
    `hookSpecificOutput.updatedToolOutput` is preserved. `field_path` is a dict key,
    a dotted path for nested keys (e.g. `file.content` for Read), `matches[i]` /
    `filenames[i]` for list elements, or "" when the response itself is a string.

    Per-tool field lists were verified against real CC 2.1.x payloads:
      - Bash:  {stdout, stderr, interrupted, isImage, noOutputExpected}
      - Read:  {type, file: {content, filePath, numLines, startLine, totalLines}}
      - REPL:  {code, result, stdout, stderr}
      - Grep:  {filenames: [...], mode, numFiles}        # plus legacy {output, matches}
      - Glob:  similar to Grep
      - Write: {type, filePath, content, structuredPatch, originalFile, userModified}
      - Edit / MultiEdit: {filePath, oldString, newString, originalFile,
                           structuredPatch: [{lines: [...]}], userModified, replaceAll}
      - ToolSearch: {query, matches: [...], total_deferred_tools}
      - Task / Agent: {content, prompt, agentId, agentType, status, ...}
                      `content` may be a string or a list of message dicts.
    """
    if not isinstance(tool_response, dict):
        text = str(tool_response) if tool_response else ""
        return [("", text)] if text else []

    if tool_name == "Bash":
        string_fields: tuple[str, ...] = ("stdout", "stderr", "output")
    elif tool_name == "Read":
        # Real shape nests under `file`; the bare keys are kept as fallback for
        # unit-test fixtures and any future API simplification.
        string_fields = ("file.content", "content", "output")
    elif tool_name == "WebFetch":
        string_fields = ("content", "output")
    elif tool_name in ("Grep", "Glob"):
        string_fields = ("output",)
    elif tool_name in ("Write", "Edit", "MultiEdit"):
        # camelCase response shape (CC 2.1.x). `content` is present on Write,
        # `originalFile` on Edit/MultiEdit and Write-over-existing. `oldString` /
        # `newString` are echoed back from the input. All four are content-bearing
        # and writable -- redact rewrites them in the response the model receives.
        string_fields = ("content", "originalFile", "oldString", "newString")
    elif tool_name == "ToolSearch":
        # Deferred-tool discovery: `query` is the user-influenced search string;
        # `matches[*]` is walked below for any string leaves (typically dicts
        # describing tool schemas, but we accept either shape).
        string_fields = ("query",)
    elif tool_name in ("Task", "Agent"):
        # `content` is sometimes a string (final assistant message) and sometimes
        # a list of message dicts -- handled below alongside the list-element case.
        string_fields = ("content", "prompt")
    else:
        string_fields = ("content", "output", "result", "text")

    fields: list[tuple[str, str]] = []
    for key in string_fields:
        val = _get_nested(tool_response, key) if "." in key else tool_response.get(key)
        if isinstance(val, str) and val:
            fields.append((key, val))

    if tool_name in ("Grep", "Glob"):
        # Legacy `matches` list AND the verified `filenames` list both expose
        # one searchable string per entry.
        for list_key in ("matches", "filenames"):
            list_val = tool_response.get(list_key)
            if isinstance(list_val, list):
                for i, item in enumerate(list_val):
                    if isinstance(item, str) and item:
                        fields.append((f"{list_key}[{i}]", item))

    if tool_name == "ToolSearch":
        # `matches` here is a list of result entries. Empirically each entry is
        # a dict describing a tool, but we also accept bare strings to stay
        # robust to schema tweaks. Dict entries fall through to the recursive
        # backstop -- their leaves are scan-only, not redactable.
        matches = tool_response.get("matches")
        if isinstance(matches, list):
            for i, item in enumerate(matches):
                if isinstance(item, str) and item:
                    fields.append((f"matches[{i}]", item))

    if tool_name in ("Edit", "MultiEdit"):
        # `structuredPatch[*].lines[*]` is the diff text presented to the model.
        # Walk it so leaked secrets in the surrounding context don't sneak past
        # via the patch body.
        patch = tool_response.get("structuredPatch")
        if isinstance(patch, list):
            for hi, hunk in enumerate(patch):
                if not isinstance(hunk, dict):
                    continue
                lines = hunk.get("lines")
                if isinstance(lines, list):
                    for li, line in enumerate(lines):
                        if isinstance(line, str) and line:
                            fields.append((f"structuredPatch[{hi}].lines[{li}]", line))

    if tool_name in ("Task", "Agent"):
        # `content` as a list-of-messages: walk each message and grab its text.
        # Each list entry is typically {type: "text", text: "..."} but we accept
        # any string leaf -- redact write-back goes back to the same path.
        content_list = tool_response.get("content")
        if isinstance(content_list, list):
            for i, item in enumerate(content_list):
                if isinstance(item, str) and item:
                    fields.append((f"content[{i}]", item))
                elif isinstance(item, dict):
                    text_val = item.get("text")
                    if isinstance(text_val, str) and text_val:
                        fields.append((f"content[{i}].text", text_val))

    return fields


_FIELD_SEGMENT_RE = re.compile(r"^([^\[]+)((?:\[\d+\])*)$")


def _parse_field_path(path: str) -> list[str | int]:
    """Split a field path like `content[3].text` into [`content`, 3, `text`].

    Supports plain keys (`stdout`), dotted keys (`file.content`), single index
    (`matches[0]`), and the mixed form (`content[3].text`) used by Task/Agent
    list-of-message responses.
    """
    parts: list[str | int] = []
    for seg in path.split("."):
        m = _FIELD_SEGMENT_RE.match(seg)
        if not m:
            raise ValueError(f"unparseable field path: {path!r}")
        parts.append(m.group(1))
        for idx in re.findall(r"\[(\d+)\]", m.group(2)):
            parts.append(int(idx))
    return parts


def _set_output_field(tool_response: dict[str, Any], field_path: str, value: str) -> None:
    """Write `value` back to `tool_response` at `field_path` (as produced by
    `_iter_output_fields`)."""
    parts = _parse_field_path(field_path)
    cur: Any = tool_response
    for part in parts[:-1]:
        cur = cur[part]
    cur[parts[-1]] = value


# Spilled-output detection: when a tool returns >50K chars Claude Code persists
# the full output to disk and replaces it with a {file_path, preview, ...} stub.
# The exact JSON shape is undocumented, so we treat any of these companion keys
# alongside `file_path` as a spill marker.
_SPILL_INDICATORS = ("truncated", "preview", "byte_size", "output_file")
_SPILLED_FILE_BYTES_CAP = 1024 * 1024  # 1 MiB cap on per-spill scan


def _detect_spilled_output(tool_response: dict[str, Any]) -> str | None:
    """Return the spilled-output file path if `tool_response` looks like a spill stub."""
    fp = tool_response.get("file_path")
    if isinstance(fp, str) and fp and any(k in tool_response for k in _SPILL_INDICATORS):
        return fp
    return None


def _read_spilled_file(path: str) -> tuple[str | None, str | None]:
    """Read up to _SPILLED_FILE_BYTES_CAP bytes from a spilled-output file.

    Returns (text, error). The path is whatever Claude Code wrote (typically a
    temp file under /tmp or platform-equivalent), so we accept any absolute
    path -- enforcing project_dir would refuse to scan CC's own buffer.
    """
    p = Path(path).expanduser()
    if not p.is_absolute():
        return None, f"spilled output path '{path}' is not absolute -- skipping scan"
    try:
        with p.open("rb") as f:
            data = f.read(_SPILLED_FILE_BYTES_CAP + 1)
    except OSError as e:
        return None, f"cannot read spilled output '{path}': {e}"
    if len(data) > _SPILLED_FILE_BYTES_CAP:
        data = data[:_SPILLED_FILE_BYTES_CAP]
    return data.decode("utf-8", errors="replace"), None


def _classify_tool_output(
    tool_name: str, tool_response: Any
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Return (redactable_fields, scan_only_fields) for `tool_response`.

    Redactable fields can be rewritten via _set_output_field and shipped back
    in `hookSpecificOutput.updatedToolOutput`. Scan-only fields can match
    block/warn rules but cannot be rewritten in place: spilled-output files
    (CC has already given the model a preview of them) and recursive walks
    over unknown dict shapes.
    """
    redactable = _iter_output_fields(tool_name, tool_response)
    scan_only: list[tuple[str, str]] = []
    if not isinstance(tool_response, dict):
        return redactable, scan_only
    fp = _detect_spilled_output(tool_response)
    if fp is not None:
        content, err = _read_spilled_file(fp)
        if err is not None:
            sys.stderr.write(f"redaction_hooks: {err}\n")
        elif content:
            scan_only.append((f"<spilled:{fp}>", content))
    if not redactable and not scan_only:
        # Unknown dict shape -- walk recursively so future schema drift doesn't
        # silently skip scanning.
        for s in _walk_strings(tool_response):
            if s:
                scan_only.append(("<recursive>", s))
    return redactable, scan_only


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
    original_input: dict[str, Any],
    redacted_content: str,
    tool_name: str,
    rule_ids: list[str],
) -> dict[str, Any]:
    """Build a response with redacted content.

    `additionalContext` informs the model that one or more rules rewrote its
    input -- the model should not be surprised when the on-disk artifact
    differs from what it tried to write. Rule IDs are included; matched text
    is never echoed.
    """
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
            "additionalContext": (
                f"Redaction hook rewrote tool input to satisfy rules: {rule_ids}"
            ),
        },
        "continue": True,
        "systemMessage": "Content was redacted before execution",
    }


def _check_file_content_rules(
    rules: list[Rule],
    paths: list[str],
    tool_name: str,
    project_dir: Path | None = None,
) -> tuple[list[Match], list[str], list[str]]:
    """Check file_content_pattern rules against file contents.

    Paths that resolve outside `project_dir` always block, regardless of rule
    action -- a security tool should refuse to assess files outside its scope.
    Other unreadable cases preserve the older behavior: block only if a
    block-action rule could have applied.

    Returns (matches, block_reasons, timed_out_rule_ids).
    """

    file_content_rules: list[Rule] = [
        r for r in rules if r.file_content_pattern and _file_tools_matches(r.file_tools, tool_name)
    ]
    if not file_content_rules or not paths:
        return [], [], []

    matches: list[Match] = []
    block_reasons: list[str] = []
    timed_out: list[str] = []

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
            try:
                with regex_timeout(DEFAULT_REGEX_TIMEOUT_SECONDS):
                    m = compiled.search(file_content)
            except RegexTimeoutError:
                timed_out.append(rule.id)
                sys.stderr.write(
                    f"redaction_hooks: file_content_pattern for rule '{rule.id}' "
                    f"exceeded {DEFAULT_REGEX_TIMEOUT_SECONDS}s on '{path}' -- skipping\n"
                )
                continue
            if m:
                matches.append(
                    Match(
                        rule=rule,
                        start=m.start(),
                        end=m.end(),
                        text=m.group(0),
                    )
                )

    return matches, block_reasons, timed_out


def handle_pre_tool_use(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle PreToolUse hook event."""
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})
    tool_use_id = data.get("tool_use_id")

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

    timeouts: list[str] = []

    # Check content-only rules
    if content and content_only_rules:
        content_matcher = PatternMatcher(content_only_rules)
        all_matches.extend(content_matcher.scan(content, "tool", tool_name))
        timeouts.extend(content_matcher.last_timeouts)

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
            timeouts.extend(content_matcher.last_timeouts)

    # Phase 1 backstop: per-tool extractor returned nothing -- maybe CC's
    # tool_input shape moved underneath us. Walk every string leaf in
    # tool_input against content_only rules. Block-action matches still fire;
    # redact gets skipped (we cannot reliably write back to an unknown shape).
    # Only content-pattern rules apply here -- combined rules need their path
    # constraint, which we cannot enforce on a recursive walk over raw strings.
    recursive_matches: list[Match] = []
    if not content and not paths and content_only_rules and tool_input:
        walk_matcher = PatternMatcher(content_only_rules)
        for s in _walk_strings(tool_input):
            if s:
                recursive_matches.extend(walk_matcher.scan(s, "tool", tool_name))
        timeouts.extend(walk_matcher.last_timeouts)
    if recursive_matches:
        _audit_schema_drift_stale_extractor(
            "PreToolUse",
            recursive_matches,
            tool=tool_name,
            tool_use_id=tool_use_id,
            project_dir=project_dir,
        )
        redact_recursive = [m for m in recursive_matches if m.rule.action == "redact"]
        non_redact_recursive = [m for m in recursive_matches if m.rule.action != "redact"]
        all_matches.extend(non_redact_recursive)
        if redact_recursive:
            rsk_ids = sorted({m.rule.id for m in redact_recursive})
            sys.stderr.write(
                f"Warning: redact rules {rsk_ids} matched only in recursive walk of "
                f"PreToolUse/{tool_name} tool_input; cannot rewrite unknown shape -- "
                "consider switching to block\n"
            )
            log_event(
                hook="PreToolUse",
                action="redact-skipped",
                rule_ids=rsk_ids,
                tool=tool_name,
                tool_use_id=tool_use_id,
                project_dir=project_dir,
            )

    # Check file_content_pattern rules (reads actual file content)
    file_content_rules = [r for r in rules if r.file_content_pattern]
    if paths and file_content_rules:
        fc_matches, fc_block_reasons, fc_timeouts = _check_file_content_rules(
            file_content_rules, paths, tool_name, project_dir
        )
        all_matches.extend(fc_matches)
        timeouts.extend(fc_timeouts)
        # Immediately block if file was unreadable
        if fc_block_reasons:
            _audit_timeouts(
                "PreToolUse",
                timeouts,
                tool=tool_name,
                tool_use_id=tool_use_id,
                project_dir=project_dir,
            )
            unreadable_ids = sorted({r.id for r in file_content_rules if r.action == "block"})
            log_event(
                hook="PreToolUse",
                action="block-unreadable",
                rule_ids=unreadable_ids,
                tool=tool_name,
                tool_use_id=tool_use_id,
                project_dir=project_dir,
            )
            json.dump(_build_block_response(fc_block_reasons), sys.stdout)
            sys.stderr.write(f"Blocked: {'; '.join(fc_block_reasons)}\n")
            return 2

    _audit_timeouts(
        "PreToolUse",
        timeouts,
        tool=tool_name,
        tool_use_id=tool_use_id,
        project_dir=project_dir,
    )

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
        tool_use_id=tool_use_id,
        project_dir=project_dir,
    )

    if result.block_reasons:
        _audit(
            "PreToolUse",
            "block",
            [m for m in all_matches if m.rule.action == "block"],
            tool=tool_name,
            tool_use_id=tool_use_id,
            project_dir=project_dir,
        )
        json.dump(_build_block_response(result.block_reasons), sys.stdout)
        sys.stderr.write(f"Blocked: {'; '.join(result.block_reasons)}\n")
        return 2

    if content and result.redacted_text and result.redacted_text != content:
        redact_matches = [m for m in all_matches if m.rule.action == "redact"]
        _audit(
            "PreToolUse",
            "redact",
            redact_matches,
            tool=tool_name,
            tool_use_id=tool_use_id,
            project_dir=project_dir,
        )
        rule_ids = sorted({m.rule.id for m in redact_matches})
        json.dump(
            _build_redact_response(tool_input, result.redacted_text, tool_name, rule_ids),
            sys.stdout,
        )
        return 0

    json.dump({"continue": True}, sys.stdout)
    return 0


def handle_user_prompt_submit(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle UserPromptSubmit hook event."""
    prompt = data.get("prompt", "")
    if not prompt:
        # Phase 2(b): if other payload keys exist and llm rules are configured,
        # the missing prompt key is a drift signal -- not a no-op session.
        rules = load_rules(project_dir)
        llm_rules = [r for r in rules if r.target in ("llm", "both")]
        if llm_rules and any(k for k in data if k != "hook_event_name"):
            _audit_schema_drift_missing_key("UserPromptSubmit", "prompt", project_dir=project_dir)
        json.dump({"continue": True}, sys.stdout)
        return 0

    rules = load_rules(project_dir)
    if not rules:
        json.dump({"continue": True}, sys.stdout)
        return 0

    matcher = PatternMatcher(rules)
    matches = matcher.scan(prompt, "llm")
    _audit_timeouts("UserPromptSubmit", matcher.last_timeouts, project_dir=project_dir)
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

    # UserPromptSubmit doesn't support updatedInput, so we cannot rewrite the
    # prompt -- but we can inject `additionalContext` so the model is aware that
    # rules matched (and ideally avoids echoing the matched content back).
    redact_matches = [m for m in matches if m.rule.action == "redact"]
    if redact_matches:
        ids = sorted({m.rule.id for m in redact_matches})
        sys.stderr.write(f"Warning: redact rules {ids} cannot modify prompts\n")
        _audit("UserPromptSubmit", "redact-skipped", redact_matches, project_dir=project_dir)
        redact_response: dict[str, Any] = {
            "continue": True,
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": (
                    f"Redaction hook: rules {ids} matched the user's prompt but "
                    "cannot rewrite it. Treat any matched content as sensitive and "
                    "do not echo it back."
                ),
            },
        }
        json.dump(redact_response, sys.stdout)
        return 0

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
    tool_use_id = data.get("tool_use_id")

    rules = load_rules(project_dir)
    if not rules:
        json.dump({"continue": True}, sys.stdout)
        return 0

    fields, scan_only = _classify_tool_output(tool_name, tool_response)
    if not fields and not scan_only:
        json.dump({"continue": True}, sys.stdout)
        return 0

    matcher = PatternMatcher(rules)
    block_reasons: list[str] = []
    warn_reasons: list[str] = []
    redacted_fields: list[tuple[str, str]] = []
    all_matches: list[Match] = []
    writable_redact: list[Match] = []
    skipped_redact: list[Match] = []
    skipped_labels: list[str] = []
    timeouts: list[str] = []
    field_match_count = 0  # for Phase 2(a) drift detection
    recursive_matches: list[Match] = []

    for field_path, content in fields:
        matches = matcher.scan(content, "tool", tool_name)
        timeouts.extend(matcher.last_timeouts)
        if not matches:
            continue
        field_match_count += len(matches)
        all_matches.extend(matches)
        writable_redact.extend(m for m in matches if m.rule.action == "redact")
        result = apply_actions(content, matches, project_dir)
        block_reasons.extend(result.block_reasons)
        warn_reasons.extend(result.warn_reasons)
        if result.redacted_text is not None and result.redacted_text != content:
            redacted_fields.append((field_path, result.redacted_text))

    for label, content in scan_only:
        matches = matcher.scan(content, "tool", tool_name)
        timeouts.extend(matcher.last_timeouts)
        if not matches:
            continue
        all_matches.extend(matches)
        if label == "<recursive>":
            recursive_matches.extend(matches)
        result = apply_actions(content, matches, project_dir)
        block_reasons.extend(result.block_reasons)
        warn_reasons.extend(result.warn_reasons)
        rmatches = [m for m in matches if m.rule.action == "redact"]
        if rmatches:
            skipped_redact.extend(rmatches)
            skipped_labels.append(label)

    # Phase 2(a): the recursive fallback caught matches that the per-tool
    # field list missed. Emit schema-drift so the operator knows the per-tool
    # extractor has gone stale (or this is a brand-new tool we haven't named).
    if recursive_matches and field_match_count == 0:
        _audit_schema_drift_stale_extractor(
            "PostToolUse",
            recursive_matches,
            tool=tool_name,
            tool_use_id=tool_use_id,
            project_dir=project_dir,
        )

    _audit_timeouts(
        "PostToolUse",
        timeouts,
        tool=tool_name,
        tool_use_id=tool_use_id,
        project_dir=project_dir,
    )

    if warn_reasons:
        _emit_warnings(warn_reasons)
    _audit(
        "PostToolUse",
        "warn",
        [m for m in all_matches if m.rule.action == "warn"],
        tool=tool_name,
        tool_use_id=tool_use_id,
        project_dir=project_dir,
    )

    if block_reasons:
        _audit(
            "PostToolUse",
            "block",
            [m for m in all_matches if m.rule.action == "block"],
            tool=tool_name,
            tool_use_id=tool_use_id,
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

    if skipped_redact:
        labels = sorted(set(skipped_labels))
        sys.stderr.write(
            f"Warning: redact rules matched in non-redactable output {labels}; "
            "output already shown to model -- consider switching to block\n"
        )
        log_event(
            hook="PostToolUse",
            action="redact-skipped",
            rule_ids=sorted({m.rule.id for m in skipped_redact}),
            tool=tool_name,
            tool_use_id=tool_use_id,
            project_dir=project_dir,
        )

    if not redacted_fields:
        # Redact rules may have matched but produced no text change (e.g. mapping
        # collision producing same string), or there were no redact matches at all.
        # Either way the tool_response was NOT rewritten -- log redact-skipped.
        if writable_redact:
            _audit(
                "PostToolUse",
                "redact-skipped",
                writable_redact,
                tool=tool_name,
                tool_use_id=tool_use_id,
                project_dir=project_dir,
            )
        json.dump({"continue": True}, sys.stdout)
        return 0

    if not isinstance(tool_response, dict):
        sys.stderr.write(f"Warning: cannot redact non-dict tool_response for {tool_name}\n")
        _audit(
            "PostToolUse",
            "redact-skipped",
            writable_redact,
            tool=tool_name,
            tool_use_id=tool_use_id,
            project_dir=project_dir,
        )
        json.dump({"continue": True}, sys.stdout)
        return 0

    for field_path, redacted in redacted_fields:
        _set_output_field(tool_response, field_path, redacted)

    _audit(
        "PostToolUse",
        "redact",
        writable_redact,
        tool=tool_name,
        tool_use_id=tool_use_id,
        project_dir=project_dir,
    )
    response = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": tool_response,
        },
        "systemMessage": "Tool output was redacted before being shown to the model",
    }
    json.dump(response, sys.stdout)
    return 0


def handle_post_tool_use_failure(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle PostToolUseFailure - scan a failed tool call's input + error.

    Verified against a real CC 2.1.x payload: the failure event carries
    `error` (a string), `tool_input`, `tool_use_id`, `is_interrupt`, and
    `duration_ms` -- no `tool_output` / `tool_response` field. PostToolUseFailure
    cannot block or rewrite (the call already failed), so matches are warned
    to stderr and audited. The handler scans the tool input (via the existing
    PreToolUse extractor) and the `error` string. This catches secrets that
    survived past PreToolUse because the failure path skipped the success-side
    PostToolUse hook.
    """
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})
    tool_error = data.get("error", "")
    tool_use_id = data.get("tool_use_id")

    rules = load_rules(project_dir)
    if not rules:
        json.dump({"continue": True}, sys.stdout)
        return 0

    # Phase 2(b): if `error` is absent (vs explicitly empty), CC may have
    # renamed the field. Emit drift if rules exist that COULD have fired.
    if "error" not in data and rules:
        _audit_schema_drift_missing_key("PostToolUseFailure", "error", project_dir=project_dir)

    matcher = PatternMatcher(rules)
    all_matches: list[Match] = []
    timeouts: list[str] = []

    input_content = _get_tool_input_content(tool_name, tool_input)
    if input_content:
        all_matches.extend(matcher.scan(input_content, "tool", tool_name))
        timeouts.extend(matcher.last_timeouts)

    if isinstance(tool_error, str) and tool_error:
        all_matches.extend(matcher.scan(tool_error, "tool", tool_name))
        timeouts.extend(matcher.last_timeouts)

    _audit_timeouts(
        "PostToolUseFailure",
        timeouts,
        tool=tool_name,
        tool_use_id=tool_use_id,
        project_dir=project_dir,
    )

    if not all_matches:
        json.dump({"continue": True}, sys.stdout)
        return 0

    rule_ids = sorted({m.rule.id for m in all_matches})
    sys.stderr.write(
        f"PostToolUseFailure warning: rules {rule_ids} matched in failed {tool_name} call\n"
    )
    # Observe-only event: a redact-action match cannot rewrite the (already
    # failed) call, so audit it as redact-skipped per the README contract.
    for rule_action, audit_action in (
        ("warn", "warn"),
        ("block", "block"),
        ("redact", "redact-skipped"),
    ):
        action_matches = [m for m in all_matches if m.rule.action == rule_action]
        if action_matches:
            _audit(
                "PostToolUseFailure",
                audit_action,
                action_matches,
                tool=tool_name,
                tool_use_id=tool_use_id,
                project_dir=project_dir,
            )

    json.dump({"continue": True}, sys.stdout)
    return 0


def _walk_strings(obj: Any) -> Iterator[str]:
    """Yield every string leaf in a JSON-shaped object (recursively)."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_strings(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_strings(item)


def handle_instructions_loaded(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle InstructionsLoaded - scan a loaded CLAUDE.md / rules file for secrets.

    Fires when Claude Code loads a memory file (CLAUDE.md, `.claude/rules/*.md`).
    The hook has no decision control per the docs, so this handler only reports
    matches via stderr + audit. Detects committed secrets in rule files and
    user-scope memory.
    """
    file_path = data.get("file_path", "")
    memory_type = data.get("memory_type", "Unknown")
    load_reason = data.get("load_reason", "unknown")

    if not file_path:
        # Phase 2(b): the entry-point key went missing.
        rules = load_rules(project_dir)
        llm_rules = [r for r in rules if r.target in ("llm", "both")]
        if llm_rules:
            _audit_schema_drift_missing_key(
                "InstructionsLoaded", "file_path", project_dir=project_dir
            )
        json.dump({"continue": True}, sys.stdout)
        return 0

    rules = load_rules(project_dir)
    llm_rules = [r for r in rules if r.target in ("llm", "both")]
    if not llm_rules:
        json.dump({"continue": True}, sys.stdout)
        return 0

    p = Path(file_path).expanduser()
    try:
        with p.open("rb") as f:
            data_bytes = f.read(_SPILLED_FILE_BYTES_CAP + 1)
    except OSError as e:
        sys.stderr.write(f"InstructionsLoaded: cannot read {file_path}: {e}\n")
        json.dump({"continue": True}, sys.stdout)
        return 0
    if len(data_bytes) > _SPILLED_FILE_BYTES_CAP:
        data_bytes = data_bytes[:_SPILLED_FILE_BYTES_CAP]
    content = data_bytes.decode("utf-8", errors="replace")

    matcher = PatternMatcher(llm_rules)
    matches = matcher.scan(content, "llm")
    _audit_timeouts("InstructionsLoaded", matcher.last_timeouts, project_dir=project_dir)

    if not matches:
        json.dump({"continue": True}, sys.stdout)
        return 0

    rule_ids = sorted({m.rule.id for m in matches})
    sys.stderr.write(
        f"InstructionsLoaded warning: rules {rule_ids} matched in {memory_type} "
        f"file {file_path} (load_reason={load_reason})\n"
    )
    # Observe-only event: redact-action match cannot rewrite a memory file
    # already loaded by CC. Surface as redact-skipped per the README contract.
    for rule_action, audit_action in (
        ("warn", "warn"),
        ("block", "block"),
        ("redact", "redact-skipped"),
    ):
        action_matches = [m for m in matches if m.rule.action == rule_action]
        if action_matches:
            _audit("InstructionsLoaded", audit_action, action_matches, project_dir=project_dir)

    json.dump({"continue": True}, sys.stdout)
    return 0


def _last_assistant_text(transcript_path: str) -> tuple[str | None, str | None]:
    """Read `transcript_path` and return (text, error).

    Returns the concatenated string content of the LAST assistant turn in the
    JSONL transcript -- the message Claude is about to deliver when Stop /
    SubagentStop fires. The exact role-key isn't documented; we accept any of
    `type`, `role`, or a nested `message.role`/`message.type`.
    """
    try:
        with Path(transcript_path).open(encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        return None, f"cannot read transcript {transcript_path}: {e}"
    last: dict[str, Any] | None = None
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        kind = obj.get("type") or obj.get("role")
        msg = obj.get("message")
        if not kind and isinstance(msg, dict):
            kind = msg.get("role") or msg.get("type")
        if kind == "assistant":
            last = obj
    if last is None:
        return "", None
    return "\n".join(_walk_strings(last)), None


def handle_stop(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle Stop / SubagentStop - scan the last assistant message for leaks.

    Real CC 2.1.x payload includes `last_assistant_message` (string) directly,
    so we read it first. We fall back to walking `transcript_path` only if the
    inline field is absent (older CC, future drift). For SubagentStop the
    payload also carries `agent_transcript_path` -- the subagent's own
    transcript -- which we prefer over the parent transcript when falling back.

    Both events fire after the message has been delivered, so we cannot redact
    in-flight. Block (decision:block) would just force Claude to keep talking,
    not unsend the message -- so this handler is warn-only.
    """
    hook_event = data.get("hook_event_name", "Stop")
    inline_msg = data.get("last_assistant_message")
    transcript_path = (
        data.get("agent_transcript_path") if hook_event == "SubagentStop" else None
    ) or data.get("transcript_path", "")

    rules = load_rules(project_dir)
    llm_rules = [r for r in rules if r.target in ("llm", "both")]
    if not llm_rules:
        json.dump({"continue": True}, sys.stdout)
        return 0

    text: str | None = None
    if isinstance(inline_msg, str) and inline_msg:
        text = inline_msg
    elif transcript_path:
        text, err = _last_assistant_text(transcript_path)
        if err is not None:
            sys.stderr.write(f"{hook_event}: {err}\n")
            json.dump({"continue": True}, sys.stdout)
            return 0
    else:
        # Neither inline message nor transcript path -- the payload is missing
        # both possible entry points. Drift signal.
        _audit_schema_drift_missing_key(
            hook_event, "last_assistant_message|transcript_path", project_dir=project_dir
        )
        json.dump({"continue": True}, sys.stdout)
        return 0

    if not text:
        json.dump({"continue": True}, sys.stdout)
        return 0

    matcher = PatternMatcher(llm_rules)
    matches = matcher.scan(text, "llm")
    _audit_timeouts(hook_event, matcher.last_timeouts, project_dir=project_dir)
    if not matches:
        json.dump({"continue": True}, sys.stdout)
        return 0

    rule_ids = sorted({m.rule.id for m in matches})
    sys.stderr.write(f"{hook_event} warning: rules {rule_ids} matched in last assistant message\n")
    # Observe-only event: the message is already on the wire; redact cannot
    # un-send it. Audit redact-action matches as redact-skipped per the README.
    for rule_action, audit_action in (
        ("warn", "warn"),
        ("block", "block"),
        ("redact", "redact-skipped"),
    ):
        action_matches = [m for m in matches if m.rule.action == rule_action]
        if action_matches:
            _audit(hook_event, audit_action, action_matches, project_dir=project_dir)
    json.dump({"continue": True}, sys.stdout)
    return 0


def _scan_transcript(
    transcript_path: str, project_dir: Path | None
) -> tuple[list[Match], list[str], str | None]:
    """Scan every string in every JSONL line of `transcript_path` against llm rules.

    Returns (matches, regex_timeouts, error). When llm rules are empty or the
    transcript is unreadable, matches is empty and an error string explains.
    """
    rules = load_rules(project_dir)
    llm_rules = [r for r in rules if r.target in ("llm", "both")]
    if not llm_rules:
        return [], [], None
    try:
        with Path(transcript_path).open(encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        return [], [], f"cannot read transcript {transcript_path}: {e}"

    matcher = PatternMatcher(llm_rules)
    matches: list[Match] = []
    timeouts: list[str] = []
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        for text in _walk_strings(obj):
            matches.extend(matcher.scan(text, "llm"))
            timeouts.extend(matcher.last_timeouts)
    return matches, timeouts, None


def handle_pre_compact(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle PreCompact hook - scan the transcript before context compaction.

    PreCompact passes `transcript_path` (a JSONL session log) on stdin rather
    than the messages inline. Compaction summarizes the transcript into a new
    context message; secrets present in earlier turns can leak into the summary
    even if they were blocked at the input layer. This handler scans the
    transcript and blocks compaction if a block-action rule matches.

    PreCompact cannot rewrite the summary, so warn and redact rules are audited
    and warned-to-stderr but allow compaction to proceed.
    """
    transcript_path = data.get("transcript_path", "")
    trigger = data.get("trigger", "unknown")

    if not transcript_path:
        # Phase 2(b)
        rules = load_rules(project_dir)
        llm_rules = [r for r in rules if r.target in ("llm", "both")]
        if llm_rules:
            _audit_schema_drift_missing_key(
                "PreCompact", "transcript_path", project_dir=project_dir
            )
        json.dump({"continue": True}, sys.stdout)
        return 0

    all_matches, timeouts, err = _scan_transcript(transcript_path, project_dir)
    if err is not None:
        sys.stderr.write(f"PreCompact: {err}\n")
        json.dump({"continue": True}, sys.stdout)
        return 0

    _audit_timeouts("PreCompact", timeouts, project_dir=project_dir)

    if not all_matches:
        json.dump({"continue": True}, sys.stdout)
        return 0

    block_matches = [m for m in all_matches if m.rule.action == "block"]
    warn_matches = [m for m in all_matches if m.rule.action == "warn"]
    redact_matches = [m for m in all_matches if m.rule.action == "redact"]

    if warn_matches:
        ids = sorted({m.rule.id for m in warn_matches})
        sys.stderr.write(f"PreCompact warning: rules {ids} matched in transcript\n")
        _audit("PreCompact", "warn", warn_matches, project_dir=project_dir)

    if redact_matches:
        ids = sorted({m.rule.id for m in redact_matches})
        sys.stderr.write(
            f"PreCompact warning: redact rules {ids} matched but cannot rewrite "
            "the compacted summary; consider blocking instead\n"
        )
        _audit("PreCompact", "redact-skipped", redact_matches, project_dir=project_dir)

    if block_matches:
        ids = sorted({m.rule.id for m in block_matches})
        _audit("PreCompact", "block", block_matches, project_dir=project_dir)
        response = {
            "decision": "block",
            "reason": (
                f"Compaction blocked: rules {ids} matched in transcript (trigger={trigger})"
            ),
            "hookSpecificOutput": {"hookEventName": "PreCompact"},
        }
        json.dump(response, sys.stdout)
        sys.stderr.write(f"PreCompact blocked: rules {ids} matched\n")
        return 2

    json.dump({"continue": True}, sys.stdout)
    return 0


def handle_post_compact(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle PostCompact - audit any rule matches in the post-compaction transcript.

    PostCompact has no decision control (per docs): compaction has already
    happened. This handler only audits + warns to surface that the summary
    contains content rules would have flagged.
    """
    transcript_path = data.get("transcript_path", "")
    trigger = data.get("trigger", "unknown")

    if not transcript_path:
        # Phase 2(b)
        rules = load_rules(project_dir)
        llm_rules = [r for r in rules if r.target in ("llm", "both")]
        if llm_rules:
            _audit_schema_drift_missing_key(
                "PostCompact", "transcript_path", project_dir=project_dir
            )
        json.dump({"continue": True}, sys.stdout)
        return 0

    all_matches, timeouts, err = _scan_transcript(transcript_path, project_dir)
    if err is not None:
        sys.stderr.write(f"PostCompact: {err}\n")
        json.dump({"continue": True}, sys.stdout)
        return 0

    _audit_timeouts("PostCompact", timeouts, project_dir=project_dir)
    if not all_matches:
        json.dump({"continue": True}, sys.stdout)
        return 0

    rule_ids = sorted({m.rule.id for m in all_matches})
    sys.stderr.write(
        f"PostCompact warning: rules {rule_ids} matched in compacted transcript "
        f"(trigger={trigger})\n"
    )
    # Observe-only event: compaction has already produced the summary; redact
    # cannot rewrite it. Surface as redact-skipped per the README contract.
    for rule_action, audit_action in (
        ("warn", "warn"),
        ("block", "block"),
        ("redact", "redact-skipped"),
    ):
        action_matches = [m for m in all_matches if m.rule.action == rule_action]
        if action_matches:
            _audit("PostCompact", audit_action, action_matches, project_dir=project_dir)

    json.dump({"continue": True}, sys.stdout)
    return 0


def _maybe_dump_payload(raw: str, event: str) -> None:
    """If `$REDACT_HOOK_DUMP_DIR` points at a writable dir, dump the raw stdin
    payload to `<dir>/<event>-<nanos>-<pid>.json`. Best-effort: failures are
    swallowed so debug instrumentation never breaks the hook itself.
    """
    import os
    import time

    dump_dir = os.environ.get("REDACT_HOOK_DUMP_DIR")
    if not dump_dir:
        return
    try:
        target = Path(dump_dir)
        target.mkdir(parents=True, exist_ok=True)
        name = f"{event or 'Unknown'}-{time.time_ns()}-{os.getpid()}.json"
        (target / name).write_text(raw, encoding="utf-8")
    except OSError as e:
        sys.stderr.write(f"redaction_hooks: REDACT_HOOK_DUMP_DIR write failed: {e}\n")


def run_hook(project_dir: Path | None = None) -> int:
    """Main hook entry point. Reads JSON from stdin, dispatches to handler.

    When `$REDACT_HOOK_DUMP_DIR` is set, the raw stdin payload is also written
    to that directory before being parsed -- a no-cost diagnostic primitive used
    by `redact verify-cc-schema` and ad-hoc payload inspection.
    """
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"Invalid JSON input: {e}\n")
        _maybe_dump_payload(raw, "InvalidJSON")
        return 1

    event = data.get("hook_event_name", "")
    _maybe_dump_payload(raw, event)

    if event == "PreToolUse":
        return handle_pre_tool_use(data, project_dir)
    if event == "PostToolUse":
        return handle_post_tool_use(data, project_dir)
    if event == "PostToolUseFailure":
        return handle_post_tool_use_failure(data, project_dir)
    if event == "UserPromptSubmit":
        return handle_user_prompt_submit(data, project_dir)
    if event == "PreCompact":
        return handle_pre_compact(data, project_dir)
    if event == "PostCompact":
        return handle_post_compact(data, project_dir)
    if event == "InstructionsLoaded":
        return handle_instructions_loaded(data, project_dir)
    if event in ("Stop", "SubagentStop"):
        return handle_stop(data, project_dir)

    # Unknown or unsupported event, allow to continue
    json.dump({"continue": True}, sys.stdout)
    return 0
