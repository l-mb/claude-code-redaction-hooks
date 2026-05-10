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

"""PostToolUseFailure handler -- observe-only scan of failed tool input + error string."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from ..config import load_rules
from ..drift import audit_missing_key
from ..extractors import get_tool_input_content
from ..matcher import PatternMatcher
from ..models import Match
from ._common import audit_matches, audit_timeouts


def handle_post_tool_use_failure(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle PostToolUseFailure - scan a failed tool call's input + error.

    Verified against a real CC 2.1.x payload: the failure event carries
    `error` (a string), `tool_input`, `tool_use_id`, `is_interrupt`, and
    `duration_ms` -- no `tool_output` / `tool_response` field. PostToolUseFailure
    cannot block or rewrite (the call already failed), so matches are warned
    to stderr and audited. Redact-action matches are surfaced as redact-skipped.
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
        audit_missing_key("PostToolUseFailure", "error", project_dir=project_dir)

    matcher = PatternMatcher(rules)
    all_matches: list[Match] = []
    timeouts: list[str] = []

    input_content = get_tool_input_content(tool_name, tool_input)
    if input_content:
        all_matches.extend(matcher.scan(input_content, "tool", tool_name))
        timeouts.extend(matcher.last_timeouts)

    if isinstance(tool_error, str) and tool_error:
        all_matches.extend(matcher.scan(tool_error, "tool", tool_name))
        timeouts.extend(matcher.last_timeouts)

    audit_timeouts(
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
            audit_matches(
                "PostToolUseFailure",
                audit_action,
                action_matches,
                tool=tool_name,
                tool_use_id=tool_use_id,
                project_dir=project_dir,
            )

    json.dump({"continue": True}, sys.stdout)
    return 0
