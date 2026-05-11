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

"""PreToolUse handler.

Scans the tool input (paths + content + on-disk file head) before CC executes
the tool. Can block (deny the call) or rewrite (`updatedInput`).
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
from ..extractors import (
    get_tool_input_content,
    get_tool_input_paths,
    walk_strings,
)
from ..matcher import PatternMatcher
from ..models import Match, Rule
from ..path_matcher import PathMatcher
from ._common import (
    audit_matches,
    audit_timeouts,
    build_block_response,
    build_redact_response,
    check_file_content_rules,
    emit_warnings,
)


@dataclass
class _RuleBuckets:
    """Rules categorised by which combination of pattern fields they use."""

    path_only: list[Rule] = field(default_factory=list)
    content_only: list[Rule] = field(default_factory=list)
    path_and_content: list[Rule] = field(default_factory=list)
    file_content: list[Rule] = field(default_factory=list)


def _categorise_rules(rules: list[Rule]) -> _RuleBuckets:
    """Bucket rules so each matcher only sees its own kind."""
    buckets = _RuleBuckets()
    for r in rules:
        if r.file_content_pattern:
            buckets.file_content.append(r)
            continue
        if r.path_pattern and r.pattern:
            buckets.path_and_content.append(r)
        elif r.path_pattern:
            buckets.path_only.append(r)
        elif r.pattern:
            buckets.content_only.append(r)
    return buckets


@dataclass
class _MatchBundle:
    """Accumulator passed through the per-bucket scan helpers."""

    matches: list[Match] = field(default_factory=list)
    timeouts: list[str] = field(default_factory=list)


def _scan_path_only(
    bundle: _MatchBundle,
    rules: list[Rule],
    paths: list[str],
    tool_name: str,
    project_dir: Path | None,
) -> None:
    if not (paths and rules):
        return
    pm = PathMatcher(rules, project_dir)
    bundle.matches.extend(pm.scan(paths, "tool", tool_name))


def _scan_content_only(
    bundle: _MatchBundle,
    rules: list[Rule],
    content: str | None,
    tool_name: str,
) -> None:
    if not (content and rules):
        return
    cm = PatternMatcher(rules)
    bundle.matches.extend(cm.scan(content, "tool", tool_name))
    bundle.timeouts.extend(cm.last_timeouts)


def _scan_path_and_content(
    bundle: _MatchBundle,
    rules: list[Rule],
    paths: list[str],
    content: str | None,
    tool_name: str,
    project_dir: Path | None,
) -> None:
    """Combined rules: path AND content must both match (path first, then content)."""
    if not (rules and paths and content):
        return
    path_matcher = PathMatcher(rules, project_dir)
    path_hits = path_matcher.scan(paths, "tool", tool_name)
    matched_ids = {m.rule.id for m in path_hits}
    rules_to_scan = [r for r in rules if r.id in matched_ids]
    if not rules_to_scan:
        return
    cm = PatternMatcher(rules_to_scan)
    bundle.matches.extend(cm.scan(content, "tool", tool_name))
    bundle.timeouts.extend(cm.last_timeouts)


def _recursive_backstop(
    rules: list[Rule],
    tool_input: dict[str, Any],
    tool_name: str,
) -> tuple[list[Match], list[str]]:
    """Phase-1 backstop: per-tool extractor returned nothing -- walk every
    string leaf in `tool_input` against content-only rules. Block-action
    matches still fire downstream; redact gets surfaced as redact-skipped
    because we cannot reliably write back to an unknown shape.
    """
    walk_matcher = PatternMatcher(rules)
    matches: list[Match] = []
    for s in walk_strings(tool_input):
        if s:
            matches.extend(walk_matcher.scan(s, "tool", tool_name))
    return matches, list(walk_matcher.last_timeouts)


def _handle_recursive_backstop(
    bundle: _MatchBundle,
    rules: list[Rule],
    tool_input: dict[str, Any],
    tool_name: str,
    tool_use_id: str | None,
    project_dir: Path | None,
) -> None:
    """Run the recursive backstop and route its matches: drift signal +
    block matches into `bundle`, redact matches into a redact-skipped audit."""
    if not (rules and tool_input):
        return
    recursive, timeouts = _recursive_backstop(rules, tool_input, tool_name)
    bundle.timeouts.extend(timeouts)
    if not recursive:
        return
    audit_stale_extractor(
        "PreToolUse",
        recursive,
        tool=tool_name,
        tool_use_id=tool_use_id,
        project_dir=project_dir,
    )
    bundle.matches.extend(m for m in recursive if m.rule.action != "redact")
    redact_recursive = [m for m in recursive if m.rule.action == "redact"]
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


def _handle_file_content_failure(
    fc_block_reasons: list[str],
    file_content_rules: list[Rule],
    bundle_timeouts: list[str],
    tool_name: str,
    tool_use_id: str | None,
    project_dir: Path | None,
) -> int:
    """Audit + emit a block response when file_content checks couldn't read the file."""
    audit_timeouts(
        "PreToolUse",
        bundle_timeouts,
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
    json.dump(build_block_response(fc_block_reasons), sys.stdout)
    sys.stderr.write(f"Blocked: {'; '.join(fc_block_reasons)}\n")
    # exit 0 + JSON: CC honors `permissionDecision: "deny"` (denies the call)
    # AND `continue: false` (halts the session). Returning 2 instead would
    # silently drop the JSON per docs (only stderr survives), so the session
    # would continue after the per-call denial.
    return 0


def _emit_block(
    block_reasons: list[str],
    matches: list[Match],
    tool_name: str,
    tool_use_id: str | None,
    project_dir: Path | None,
) -> int:
    audit_matches(
        "PreToolUse",
        "block",
        [m for m in matches if m.rule.action == "block"],
        tool=tool_name,
        tool_use_id=tool_use_id,
        project_dir=project_dir,
    )
    json.dump(build_block_response(block_reasons), sys.stdout)
    sys.stderr.write(f"Blocked: {'; '.join(block_reasons)}\n")
    # See _handle_file_content_failure for why exit 0 + JSON over exit 2.
    return 0


def _emit_redact(
    redacted_text: str,
    matches: list[Match],
    tool_input: dict[str, Any],
    tool_name: str,
    tool_use_id: str | None,
    project_dir: Path | None,
) -> int:
    redact_matches = [m for m in matches if m.rule.action == "redact"]
    audit_matches(
        "PreToolUse",
        "redact",
        redact_matches,
        tool=tool_name,
        tool_use_id=tool_use_id,
        project_dir=project_dir,
    )
    rule_ids = sorted({m.rule.id for m in redact_matches})
    json.dump(
        build_redact_response(tool_input, redacted_text, tool_name, rule_ids),
        sys.stdout,
    )
    return 0


def _emit_continue() -> int:
    json.dump({"continue": True}, sys.stdout)
    return 0


def handle_pre_tool_use(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle PreToolUse hook event."""
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})
    tool_use_id = data.get("tool_use_id")

    rules = load_rules(project_dir)
    if not rules:
        return _emit_continue()

    buckets = _categorise_rules(rules)
    paths = get_tool_input_paths(tool_name, tool_input)
    content = get_tool_input_content(tool_name, tool_input)

    bundle = _MatchBundle()
    _scan_path_only(bundle, buckets.path_only, paths, tool_name, project_dir)
    _scan_content_only(bundle, buckets.content_only, content, tool_name)
    _scan_path_and_content(bundle, buckets.path_and_content, paths, content, tool_name, project_dir)
    if not content and not paths:
        # Only content-pattern rules apply on the recursive walk -- combined
        # rules need their path constraint, which we cannot enforce on raw
        # strings.
        _handle_recursive_backstop(
            bundle, buckets.content_only, tool_input, tool_name, tool_use_id, project_dir
        )

    # file_content_pattern rules can short-circuit on unreadable target files.
    if paths and buckets.file_content:
        fc_matches, fc_block_reasons, fc_timeouts = check_file_content_rules(
            buckets.file_content, paths, tool_name, project_dir
        )
        bundle.matches.extend(fc_matches)
        bundle.timeouts.extend(fc_timeouts)
        if fc_block_reasons:
            return _handle_file_content_failure(
                fc_block_reasons,
                buckets.file_content,
                bundle.timeouts,
                tool_name,
                tool_use_id,
                project_dir,
            )

    audit_timeouts(
        "PreToolUse",
        bundle.timeouts,
        tool=tool_name,
        tool_use_id=tool_use_id,
        project_dir=project_dir,
    )

    if not bundle.matches:
        return _emit_continue()

    result = apply_actions(content or "", bundle.matches, project_dir)

    if result.warn_reasons:
        emit_warnings(result.warn_reasons)
    audit_matches(
        "PreToolUse",
        "warn",
        [m for m in bundle.matches if m.rule.action == "warn"],
        tool=tool_name,
        tool_use_id=tool_use_id,
        project_dir=project_dir,
    )

    if result.block_reasons:
        return _emit_block(
            result.block_reasons, bundle.matches, tool_name, tool_use_id, project_dir
        )

    if content and result.redacted_text and result.redacted_text != content:
        return _emit_redact(
            result.redacted_text, bundle.matches, tool_input, tool_name, tool_use_id, project_dir
        )

    return _emit_continue()
