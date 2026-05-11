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

"""PostToolUse handler.

Scans the tool response and rewrites it via `updatedToolOutput`. Spilled
output and unknown response shapes are scan-only (block can fire, redact
becomes redact-skipped).
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..actions import apply_actions
from ..audit import log_event
from ..config import load_rules
from ..drift import audit_stale_extractor
from ..extractors import classify_tool_output, set_output_field
from ..matcher import PatternMatcher
from ..models import Match
from ._common import audit_matches, audit_timeouts, emit_warnings


@dataclass
class _ScanState:
    block_reasons: list[str] = field(default_factory=list)
    warn_reasons: list[str] = field(default_factory=list)
    redacted_fields: list[tuple[str, str]] = field(default_factory=list)
    all_matches: list[Match] = field(default_factory=list)
    writable_redact: list[Match] = field(default_factory=list)
    skipped_redact: list[Match] = field(default_factory=list)
    skipped_labels: list[str] = field(default_factory=list)
    timeouts: list[str] = field(default_factory=list)
    field_match_count: int = 0
    recursive_matches: list[Match] = field(default_factory=list)


def _scan_redactable_fields(
    state: _ScanState,
    matcher: PatternMatcher,
    fields: list[tuple[str, str]],
    tool_name: str,
    project_dir: Path | None,
) -> None:
    for field_path, content in fields:
        matches = matcher.scan(content, "tool", tool_name)
        state.timeouts.extend(matcher.last_timeouts)
        if not matches:
            continue
        state.field_match_count += len(matches)
        state.all_matches.extend(matches)
        state.writable_redact.extend(m for m in matches if m.rule.action == "redact")
        result = apply_actions(content, matches, project_dir)
        state.block_reasons.extend(result.block_reasons)
        state.warn_reasons.extend(result.warn_reasons)
        if result.redacted_text is not None and result.redacted_text != content:
            state.redacted_fields.append((field_path, result.redacted_text))


def _scan_scan_only_fields(
    state: _ScanState,
    matcher: PatternMatcher,
    scan_only: list[tuple[str, str]],
    tool_name: str,
    project_dir: Path | None,
) -> None:
    for label, content in scan_only:
        matches = matcher.scan(content, "tool", tool_name)
        state.timeouts.extend(matcher.last_timeouts)
        if not matches:
            continue
        state.all_matches.extend(matches)
        if label == "<recursive>":
            state.recursive_matches.extend(matches)
        result = apply_actions(content, matches, project_dir)
        state.block_reasons.extend(result.block_reasons)
        state.warn_reasons.extend(result.warn_reasons)
        rmatches = [m for m in matches if m.rule.action == "redact"]
        if rmatches:
            state.skipped_redact.extend(rmatches)
            state.skipped_labels.append(label)


def _emit_block(
    state: _ScanState,
    tool_name: str,
    tool_use_id: str | None,
    project_dir: Path | None,
) -> int:
    audit_matches(
        "PostToolUse",
        "block",
        [m for m in state.all_matches if m.rule.action == "block"],
        tool=tool_name,
        tool_use_id=tool_use_id,
        project_dir=project_dir,
    )
    response = {
        "decision": "block",
        "reason": f"Tool output blocked: {'; '.join(state.block_reasons)}",
        "hookSpecificOutput": {"hookEventName": "PostToolUse"},
    }
    json.dump(response, sys.stdout)
    sys.stderr.write(f"Tool output blocked: {'; '.join(state.block_reasons)}\n")
    # PostToolUse intentionally stays on exit 2 (does NOT use the
    # `continue: false` halt path that PreToolUse / UserPromptSubmit /
    # PreCompact use). The tool has already executed by the time
    # PostToolUse fires; halting the session would only delay the next
    # turn -- it cannot un-ship the leaked content. The exit-2 path
    # feeds the stderr error back to the model so it knows the output
    # was withheld, then lets it react.
    return 2


def _emit_redact_skipped(
    state: _ScanState,
    tool_name: str,
    tool_use_id: str | None,
    project_dir: Path | None,
) -> None:
    """Surface scan-only-field redact matches as redact-skipped."""
    if not state.skipped_redact:
        return
    labels = sorted(set(state.skipped_labels))
    sys.stderr.write(
        f"Warning: redact rules matched in non-redactable output {labels}; "
        "output already shown to model -- consider switching to block\n"
    )
    log_event(
        hook="PostToolUse",
        action="redact-skipped",
        rule_ids=sorted({m.rule.id for m in state.skipped_redact}),
        tool=tool_name,
        tool_use_id=tool_use_id,
        project_dir=project_dir,
    )


def _emit_no_redact_change(
    state: _ScanState,
    tool_name: str,
    tool_use_id: str | None,
    project_dir: Path | None,
) -> int:
    """Redact rules matched but produced no text change (or no redact matches)."""
    if state.writable_redact:
        audit_matches(
            "PostToolUse",
            "redact-skipped",
            state.writable_redact,
            tool=tool_name,
            tool_use_id=tool_use_id,
            project_dir=project_dir,
        )
    json.dump({"continue": True}, sys.stdout)
    return 0


def _emit_non_dict_response(
    state: _ScanState,
    tool_name: str,
    tool_use_id: str | None,
    project_dir: Path | None,
) -> int:
    sys.stderr.write(f"Warning: cannot redact non-dict tool_response for {tool_name}\n")
    audit_matches(
        "PostToolUse",
        "redact-skipped",
        state.writable_redact,
        tool=tool_name,
        tool_use_id=tool_use_id,
        project_dir=project_dir,
    )
    json.dump({"continue": True}, sys.stdout)
    return 0


def _emit_redacted(
    state: _ScanState,
    tool_response: dict[str, Any],
    tool_name: str,
    tool_use_id: str | None,
    project_dir: Path | None,
) -> int:
    for field_path, redacted in state.redacted_fields:
        set_output_field(tool_response, field_path, redacted)

    audit_matches(
        "PostToolUse",
        "redact",
        state.writable_redact,
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


def handle_post_tool_use(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle PostToolUse hook event - scan tool output and apply block/redact actions.

    Redactions are written back to the original tool_response shape via
    hookSpecificOutput.updatedToolOutput (Claude Code v2.1.121+). For non-dict
    responses we cannot reliably reconstruct the schema, so redactions are
    skipped (audit action `redact-skipped`) with a stderr warning.
    """
    tool_name = data.get("tool_name", "")
    tool_response = data.get("tool_response")
    tool_use_id = data.get("tool_use_id")

    rules = load_rules(project_dir)
    if not rules:
        json.dump({"continue": True}, sys.stdout)
        return 0

    fields, scan_only = classify_tool_output(tool_name, tool_response)
    if not fields and not scan_only:
        json.dump({"continue": True}, sys.stdout)
        return 0

    matcher = PatternMatcher(rules)
    state = _ScanState()
    _scan_redactable_fields(state, matcher, fields, tool_name, project_dir)
    _scan_scan_only_fields(state, matcher, scan_only, tool_name, project_dir)

    # Phase 2(a): the recursive fallback caught matches that the per-tool
    # field list missed. Emit schema-drift so the operator knows the per-tool
    # extractor has gone stale (or this is a brand-new tool we haven't named).
    if state.recursive_matches and state.field_match_count == 0:
        audit_stale_extractor(
            "PostToolUse",
            state.recursive_matches,
            tool=tool_name,
            tool_use_id=tool_use_id,
            project_dir=project_dir,
        )

    audit_timeouts(
        "PostToolUse",
        state.timeouts,
        tool=tool_name,
        tool_use_id=tool_use_id,
        project_dir=project_dir,
    )

    if state.warn_reasons:
        emit_warnings(state.warn_reasons)
    audit_matches(
        "PostToolUse",
        "warn",
        [m for m in state.all_matches if m.rule.action == "warn"],
        tool=tool_name,
        tool_use_id=tool_use_id,
        project_dir=project_dir,
    )

    if state.block_reasons:
        return _emit_block(state, tool_name, tool_use_id, project_dir)

    _emit_redact_skipped(state, tool_name, tool_use_id, project_dir)

    if not state.redacted_fields:
        return _emit_no_redact_change(state, tool_name, tool_use_id, project_dir)

    if not isinstance(tool_response, dict):
        return _emit_non_dict_response(state, tool_name, tool_use_id, project_dir)

    return _emit_redacted(state, tool_response, tool_name, tool_use_id, project_dir)
