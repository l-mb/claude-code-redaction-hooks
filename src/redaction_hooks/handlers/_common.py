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

"""Helpers shared across hook handlers.

Audit-log shorthands, response builders, and the file_content_pattern check.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

from ..audit import log_event
from ..extractors import file_tools_matches, read_file_head
from ..matcher import DEFAULT_REGEX_TIMEOUT_SECONDS, RegexTimeoutError, regex_timeout
from ..models import Match, Rule
from ..path_matcher import PathMatcher


def audit_matches(
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


def audit_timeouts(
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


def emit_warnings(warn_reasons: list[str]) -> None:
    """Write warning messages to stderr."""
    for reason in warn_reasons:
        sys.stderr.write(f"Warning: {reason}\n")


def build_block_response(reasons: list[str]) -> dict[str, Any]:
    """Build a blocking response for PreToolUse.

    Returns the rich JSON CC honors on exit code 0 (per docs): the
    `permissionDecision: "deny"` denies the tool call AND `continue: false`
    halts the rest of the session. Empirically (CC 2.1.138): halt is honored
    between turns; within a parallel tool batch, every call's PreToolUse
    still fires (and is individually denied) before the halt takes effect on
    the next batch.
    """
    joined = "; ".join(reasons)
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": joined,
        },
        "continue": False,
        "stopReason": f"Blocked by redaction rules: {joined}",
    }


def build_decision_block_response(event_name: str, reasons: list[str]) -> dict[str, Any]:
    """Build a top-level `decision: "block"` response with halt fields.

    Used by events whose decision pattern is top-level `decision: "block"`:
    UserPromptSubmit, UserPromptExpansion, PostToolBatch, PreCompact (per
    docs https://code.claude.com/docs/en/hooks). Always sets
    `continue: false` + `stopReason` so any blocking match halts the whole
    session, not just the current event -- a blocked secret-leak pattern
    means the user needs to re-engage, not silently retry.
    """
    joined = "; ".join(reasons)
    blocked = f"Blocked by redaction rules: {joined}"
    return {
        "decision": "block",
        "reason": blocked,
        "continue": False,
        "stopReason": blocked,
        "hookSpecificOutput": {"hookEventName": event_name},
    }


def build_redact_response(
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


def check_file_content_rules(
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
        r for r in rules if r.file_content_pattern and file_tools_matches(r.file_tools, tool_name)
    ]
    if not file_content_rules or not paths:
        return [], [], []

    matches: list[Match] = []
    block_reasons: list[str] = []
    timed_out: list[str] = []

    for path in paths:
        file_content, error = read_file_head(path, project_dir)
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
