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

"""PostToolBatch handler.

Fires after a full batch of parallel tool calls resolves, before the next
model call. Carries a `tool_calls` array; `tool_response` per entry is a
serialized string or content-block array (NOT the structured Output shape
that PostToolUse uses), so we walk every string leaf rather than driving
named-field extractors.

Decision pattern: top-level `decision: "block"`. Outputs have already been
shipped to the model context, so redact-action matches surface as
redact-skipped audits (cannot be rewritten after the batch).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from ..config import load_rules
from ..drift import audit_missing_key
from ..extractors import walk_strings
from ..matcher import PatternMatcher
from ._common import audit_matches, audit_timeouts, build_decision_block_response, emit_warnings


def handle_post_tool_batch(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle PostToolBatch - scan every tool_response in the resolved batch."""
    tool_calls = data.get("tool_calls")
    if not isinstance(tool_calls, list) or not tool_calls:
        # Drift signal: the entry-point key is absent or empty; if rules
        # would have applied, log it so we notice schema drift.
        rules = load_rules(project_dir)
        if any(r.target in ("tool", "both") for r in rules) and any(
            k for k in data if k != "hook_event_name"
        ):
            audit_missing_key("PostToolBatch", "tool_calls", project_dir=project_dir)
        json.dump({"continue": True}, sys.stdout)
        return 0

    rules = load_rules(project_dir)
    tool_rules = [r for r in rules if r.target in ("tool", "both")]
    if not tool_rules:
        json.dump({"continue": True}, sys.stdout)
        return 0

    matcher = PatternMatcher(tool_rules)
    all_matches = []
    for entry in tool_calls:
        if not isinstance(entry, dict):
            continue
        tool_name = entry.get("tool_name", "")
        # Walk every string leaf of the entry; tool_response can be a string,
        # a list of content blocks, or a dict -- walk_strings handles all.
        for s in walk_strings(entry):
            if s:
                all_matches.extend(matcher.scan(s, "tool", tool_name))

    audit_timeouts("PostToolBatch", matcher.last_timeouts, project_dir=project_dir)
    if not all_matches:
        json.dump({"continue": True}, sys.stdout)
        return 0

    block_matches = [m for m in all_matches if m.rule.action == "block"]
    warn_matches = [m for m in all_matches if m.rule.action == "warn"]
    redact_matches = [m for m in all_matches if m.rule.action == "redact"]

    if warn_matches:
        warn_ids = sorted({m.rule.id for m in warn_matches})
        emit_warnings([f"PostToolBatch warn rules matched: {warn_ids}"])
        audit_matches("PostToolBatch", "warn", warn_matches, project_dir=project_dir)

    if redact_matches:
        ids = sorted({m.rule.id for m in redact_matches})
        sys.stderr.write(
            f"PostToolBatch warning: redact rules {ids} matched in batch output "
            "but cannot rewrite responses already shipped to context\n"
        )
        audit_matches("PostToolBatch", "redact-skipped", redact_matches, project_dir=project_dir)

    if block_matches:
        ids = sorted({m.rule.id for m in block_matches})
        audit_matches("PostToolBatch", "block", block_matches, project_dir=project_dir)
        reason = f"rules {ids} matched in batched tool output"
        json.dump(build_decision_block_response("PostToolBatch", [reason]), sys.stdout)
        sys.stderr.write(f"PostToolBatch blocked: rules {ids} matched\n")
        return 0

    json.dump({"continue": True}, sys.stdout)
    return 0
