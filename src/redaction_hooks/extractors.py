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

"""Per-tool extractors over Claude Code hook payloads.

These functions translate the undocumented `tool_input` / `tool_response`
shapes that CC hands to a hook into the (path, content, list-of-fields)
inputs that the matchers, action layer, and handlers consume.

The shape lookups are validated against the captured payload corpus in
`tests/fixtures/cc-payloads/` (see `redact verify-cc-schema`). When CC
ships a shape change, only the per-tool tables here need an update.
"""

from __future__ import annotations

import re
import shlex
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

# ----- shell-token classification ---------------------------------------------

# Path-like tokens start with ~, ., or /. Anything else with a `/` is treated
# as path-bearing too (e.g. `src/main.py`).
_PATH_PATTERN = re.compile(r"^[~./]")
_URL_PATTERN = re.compile(r"^https?://", re.IGNORECASE)
# Fallback regex for path extraction when shlex fails on an unbalanced quote.
_FALLBACK_PATH_RE = re.compile(r"(?:^|[\s;|&])([~/][^\s;|&]+|\.\.?/[^\s;|&]+)")
# Splits a compound shell command on ; && || | newline so each subcommand
# can be tokenized independently.
_SHELL_SEPARATORS = re.compile(r"\s*(?:&&|\|\||;|\||\n)\s*")
# Shell binaries whose `-c <inner>` argument should be recursively re-tokenized.
# Matched on Path.name so `/usr/bin/bash` and `bash` are both recognised.
_SHELL_BINARIES = frozenset({"bash", "sh", "dash", "zsh", "ksh"})

# ----- tool grouping -----------------------------------------------------------

READ_TOOLS = frozenset({"Read"})
WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit"})
FILE_TOOLS = READ_TOOLS | WRITE_TOOLS

# ----- spill detection ---------------------------------------------------------

# When a tool returns >50K chars CC persists the full output to disk and
# replaces it with a `{file_path, preview, ...}` stub. The exact JSON shape is
# undocumented, so we treat any of these companion keys alongside `file_path`
# as a spill marker.
_SPILL_INDICATORS = ("truncated", "preview", "byte_size", "output_file")
SPILLED_FILE_BYTES_CAP = 1024 * 1024  # 1 MiB cap on per-spill scan


# =============================================================================
# Path extraction from Bash commands
# =============================================================================


def extract_path_from_token(token: str) -> str | None:
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


def extract_bash_paths(command: str) -> list[str]:
    """Extract path-like tokens from a shell command.

    Compound commands are split on `;`, `&&`, `||`, `|`, and newlines so each
    subcommand is tokenized independently. A token is a path if it starts with
    `/`, `./`, `../`, or `~`, or if it contains `/` and is not a flag.
    `--key=value` tokens contribute `value` (not the whole `--key=value`).
    Wrapped shells (`bash -c "<inner>"`, `sh -c '<inner>'`, etc.) are recursed
    into so paths inside the wrapped command are not missed.
    """
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
            paths.extend(extract_bash_paths(inner))
        for token in tokens:
            extracted = extract_path_from_token(token)
            if extracted is not None:
                paths.append(extracted)
    return paths


# =============================================================================
# Tool-input extraction (path + content)
# =============================================================================


def get_tool_input_paths(tool_name: str, tool_input: dict[str, Any]) -> list[str]:
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
        return extract_bash_paths(command)
    if tool_name in ("Grep", "Glob"):
        path = tool_input.get("path")
        return [path] if path else []
    return []


def get_tool_input_content(tool_name: str, tool_input: dict[str, Any]) -> str | None:
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


# =============================================================================
# Tool-output extraction (per-tool field walk + write-back)
# =============================================================================


def _get_nested(obj: Any, dotted: str) -> Any:
    """Walk `obj` along a dotted key path; return None if any step is missing."""
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


# Per-tool top-level string-field lists. Order is preserved -- iter_output_fields
# walks them in declaration order so write-back goes to the same key the model
# eventually reads.
_OUTPUT_STRING_FIELDS: dict[str, tuple[str, ...]] = {
    "Bash": ("stdout", "stderr", "output"),
    # Real Read shape nests under `file`; the bare keys are kept as fallback for
    # unit-test fixtures and any future API simplification.
    "Read": ("file.content", "content", "output"),
    "WebFetch": ("content", "output"),
    "Grep": ("output",),
    "Glob": ("output",),
    # camelCase response shape (CC 2.1.x). `content` is present on Write,
    # `originalFile` on Edit/MultiEdit and Write-over-existing. `oldString` /
    # `newString` are echoed back from the input. All four are content-bearing
    # and writable -- redact rewrites them in the response the model receives.
    "Write": ("content", "originalFile", "oldString", "newString"),
    "Edit": ("content", "originalFile", "oldString", "newString"),
    "MultiEdit": ("content", "originalFile", "oldString", "newString"),
    # Deferred-tool discovery: `query` is the user-influenced search string;
    # `matches[*]` is walked below for any string leaves (typically dicts
    # describing tool schemas, but we accept either shape).
    "ToolSearch": ("query",),
    # `content` is sometimes a string (final assistant message) and sometimes
    # a list of message dicts -- handled in the per-tool extras below.
    "Task": ("content", "prompt"),
    "Agent": ("content", "prompt"),
}
_DEFAULT_OUTPUT_STRING_FIELDS = ("content", "output", "result", "text")


def _grep_glob_extras(tool_response: dict[str, Any]) -> list[tuple[str, str]]:
    """Legacy `matches` and verified `filenames` lists for Grep / Glob."""
    extras: list[tuple[str, str]] = []
    for list_key in ("matches", "filenames"):
        list_val = tool_response.get(list_key)
        if isinstance(list_val, list):
            for i, item in enumerate(list_val):
                if isinstance(item, str) and item:
                    extras.append((f"{list_key}[{i}]", item))
    return extras


def _toolsearch_matches_extras(tool_response: dict[str, Any]) -> list[tuple[str, str]]:
    """`matches` list of result entries for ToolSearch.

    Empirically each entry is a dict describing a tool, but we also accept
    bare strings to stay robust to schema tweaks. Dict entries fall through
    to the recursive backstop -- their leaves are scan-only, not redactable.
    """
    matches = tool_response.get("matches")
    if not isinstance(matches, list):
        return []
    return [
        (f"matches[{i}]", item) for i, item in enumerate(matches) if isinstance(item, str) and item
    ]


def _structured_patch_extras(tool_response: dict[str, Any]) -> list[tuple[str, str]]:
    """`structuredPatch[*].lines[*]` is the diff text presented to the model.

    Walk it so leaked secrets in the surrounding context don't sneak past
    via the patch body.
    """
    extras: list[tuple[str, str]] = []
    patch = tool_response.get("structuredPatch")
    if not isinstance(patch, list):
        return extras
    for hi, hunk in enumerate(patch):
        if not isinstance(hunk, dict):
            continue
        lines = hunk.get("lines")
        if isinstance(lines, list):
            for li, line in enumerate(lines):
                if isinstance(line, str) and line:
                    extras.append((f"structuredPatch[{hi}].lines[{li}]", line))
    return extras


def _task_content_list_extras(tool_response: dict[str, Any]) -> list[tuple[str, str]]:
    """`content` as a list-of-messages: walk each message and grab its text.

    Each list entry is typically {type: "text", text: "..."} but we accept
    any string leaf -- redact write-back goes back to the same path.
    """
    extras: list[tuple[str, str]] = []
    content_list = tool_response.get("content")
    if not isinstance(content_list, list):
        return extras
    for i, item in enumerate(content_list):
        if isinstance(item, str) and item:
            extras.append((f"content[{i}]", item))
        elif isinstance(item, dict):
            text_val = item.get("text")
            if isinstance(text_val, str) and text_val:
                extras.append((f"content[{i}].text", text_val))
    return extras


# Per-tool extras callbacks that surface list-of-things buried inside the
# response dict. Keyed by tool name; each callable takes the response dict and
# returns extra (field_path, content) tuples.
_OUTPUT_EXTRAS: dict[str, list[Any]] = {
    "Grep": [_grep_glob_extras],
    "Glob": [_grep_glob_extras],
    "ToolSearch": [_toolsearch_matches_extras],
    "Edit": [_structured_patch_extras],
    "MultiEdit": [_structured_patch_extras],
    "Task": [_task_content_list_extras],
    "Agent": [_task_content_list_extras],
}


def iter_output_fields(tool_name: str, tool_response: Any) -> list[tuple[str, str]]:
    """Return (field_path, content) pairs for each scannable string field in tool_response.

    Each field is scanned and redacted independently so the response shape required by
    `hookSpecificOutput.updatedToolOutput` is preserved. `field_path` is a dict key,
    a dotted path for nested keys (e.g. `file.content` for Read), `matches[i]` /
    `filenames[i]` for list elements, or "" when the response itself is a string.
    """
    if not isinstance(tool_response, dict):
        text = str(tool_response) if tool_response else ""
        return [("", text)] if text else []

    string_fields = _OUTPUT_STRING_FIELDS.get(tool_name, _DEFAULT_OUTPUT_STRING_FIELDS)
    fields: list[tuple[str, str]] = []
    for key in string_fields:
        val = _get_nested(tool_response, key) if "." in key else tool_response.get(key)
        if isinstance(val, str) and val:
            fields.append((key, val))

    for extras_fn in _OUTPUT_EXTRAS.get(tool_name, []):
        fields.extend(extras_fn(tool_response))

    return fields


# =============================================================================
# Field-path parsing + write-back
# =============================================================================


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


def set_output_field(tool_response: dict[str, Any], field_path: str, value: str) -> None:
    """Write `value` back to `tool_response` at `field_path`.

    `field_path` is the format produced by `iter_output_fields`.
    """
    parts = _parse_field_path(field_path)
    cur: Any = tool_response
    for part in parts[:-1]:
        cur = cur[part]
    cur[parts[-1]] = value


# =============================================================================
# Spill detection
# =============================================================================


def _detect_spilled_output(tool_response: dict[str, Any]) -> str | None:
    """Return the spilled-output file path if `tool_response` looks like a spill stub."""
    fp = tool_response.get("file_path")
    if isinstance(fp, str) and fp and any(k in tool_response for k in _SPILL_INDICATORS):
        return fp
    return None


def _read_spilled_file(path: str) -> tuple[str | None, str | None]:
    """Read up to SPILLED_FILE_BYTES_CAP bytes from a spilled-output file.

    Returns (text, error). The path is whatever Claude Code wrote (typically a
    temp file under /tmp or platform-equivalent), so we accept any absolute
    path -- enforcing project_dir would refuse to scan CC's own buffer.
    """
    p = Path(path).expanduser()
    if not p.is_absolute():
        return None, f"spilled output path '{path}' is not absolute -- skipping scan"
    try:
        with p.open("rb") as f:
            data = f.read(SPILLED_FILE_BYTES_CAP + 1)
    except OSError as e:
        return None, f"cannot read spilled output '{path}': {e}"
    if len(data) > SPILLED_FILE_BYTES_CAP:
        data = data[:SPILLED_FILE_BYTES_CAP]
    return data.decode("utf-8", errors="replace"), None


# =============================================================================
# JSON walk + classification
# =============================================================================


def walk_strings(obj: Any) -> Iterator[str]:
    """Yield every string leaf in a JSON-shaped object (recursively)."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from walk_strings(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from walk_strings(item)


def classify_tool_output(
    tool_name: str, tool_response: Any
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Return (redactable_fields, scan_only_fields) for `tool_response`.

    Redactable fields can be rewritten via set_output_field and shipped back
    in `hookSpecificOutput.updatedToolOutput`. Scan-only fields can match
    block/warn rules but cannot be rewritten in place: spilled-output files
    (CC has already given the model a preview of them) and recursive walks
    over unknown dict shapes.
    """
    redactable = iter_output_fields(tool_name, tool_response)
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
        for s in walk_strings(tool_response):
            if s:
                scan_only.append(("<recursive>", s))
    return redactable, scan_only


# =============================================================================
# Project-bound file head reader (used by file_content_pattern rules)
# =============================================================================


def file_tools_matches(file_tools: str | None, tool_name: str) -> bool:
    """Check if tool_name matches the file_tools filter."""
    if file_tools is None:
        return tool_name in FILE_TOOLS
    if file_tools == "read":
        return tool_name in READ_TOOLS
    if file_tools == "write":
        return tool_name in WRITE_TOOLS
    if file_tools == "rw":
        return tool_name in FILE_TOOLS
    return False


def read_file_head(
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
