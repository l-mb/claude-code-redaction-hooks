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

"""UserPromptSubmit handler.

Can block the prompt outright. Cannot rewrite it (CC's UserPromptSubmit
contract has no `updatedInput`), so redact-action matches are surfaced as
redact-skipped audits and via `additionalContext` so the model knows to
treat the matched content as sensitive.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from ..actions import apply_actions
from ..config import load_rules
from ..drift import audit_missing_key
from ..matcher import PatternMatcher
from ._common import audit_matches, audit_timeouts, build_decision_block_response, emit_warnings


def handle_user_prompt_submit(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle UserPromptSubmit hook event."""
    prompt = data.get("prompt", "")
    if not prompt:
        # Phase 2(b): if other payload keys exist and llm rules are configured,
        # the missing prompt key is a drift signal -- not a no-op session.
        rules = load_rules(project_dir)
        llm_rules = [r for r in rules if r.target in ("llm", "both")]
        if llm_rules and any(k for k in data if k != "hook_event_name"):
            audit_missing_key("UserPromptSubmit", "prompt", project_dir=project_dir)
        json.dump({"continue": True}, sys.stdout)
        return 0

    rules = load_rules(project_dir)
    if not rules:
        json.dump({"continue": True}, sys.stdout)
        return 0

    matcher = PatternMatcher(rules)
    matches = matcher.scan(prompt, "llm")
    audit_timeouts("UserPromptSubmit", matcher.last_timeouts, project_dir=project_dir)
    if not matches:
        json.dump({"continue": True}, sys.stdout)
        return 0

    result = apply_actions(prompt, matches, project_dir)

    if result.warn_reasons:
        emit_warnings(result.warn_reasons)
    audit_matches(
        "UserPromptSubmit",
        "warn",
        [m for m in matches if m.rule.action == "warn"],
        project_dir=project_dir,
    )

    if result.block_reasons:
        audit_matches(
            "UserPromptSubmit",
            "block",
            [m for m in matches if m.rule.action == "block"],
            project_dir=project_dir,
        )
        json.dump(
            build_decision_block_response("UserPromptSubmit", result.block_reasons), sys.stdout
        )
        sys.stderr.write(f"Prompt blocked: {'; '.join(result.block_reasons)}\n")
        # exit 0 + JSON: CC honors `decision: "block"` (rejects the prompt) AND
        # `continue: false` (halts the rest of the session). exit 2 would drop
        # the JSON per docs and just feed stderr to Claude on the next turn.
        return 0

    # UserPromptSubmit doesn't support updatedInput, so we cannot rewrite the
    # prompt -- but we can inject `additionalContext` so the model is aware that
    # rules matched (and ideally avoids echoing the matched content back).
    redact_matches = [m for m in matches if m.rule.action == "redact"]
    if redact_matches:
        ids = sorted({m.rule.id for m in redact_matches})
        sys.stderr.write(f"Warning: redact rules {ids} cannot modify prompts\n")
        audit_matches("UserPromptSubmit", "redact-skipped", redact_matches, project_dir=project_dir)
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
