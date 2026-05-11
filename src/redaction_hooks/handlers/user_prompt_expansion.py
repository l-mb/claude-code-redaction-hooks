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

"""UserPromptExpansion handler.

Fires when a user-typed slash command (`/skillname args`) expands into a
prompt before reaching Claude. Per CC docs, this path bypasses both
`UserPromptSubmit` and `PreToolUse` -- without coverage here, secrets
embedded in slash-command arguments slip past every other scan point.

Decision pattern: top-level `decision: "block"` (no `updatedInput`
support per docs), so redact-action matches surface as redact-skipped
audits + an `additionalContext` warning to the model.
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


def handle_user_prompt_expansion(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle UserPromptExpansion - scan the expanded prompt for llm-target rules."""
    prompt = data.get("prompt", "")
    if not prompt:
        # Drift signal: command_name present but expanded prompt missing
        # means CC sent us a payload our handler can't scan.
        rules = load_rules(project_dir)
        llm_rules = [r for r in rules if r.target in ("llm", "both")]
        if llm_rules and data.get("command_name"):
            audit_missing_key("UserPromptExpansion", "prompt", project_dir=project_dir)
        json.dump({"continue": True}, sys.stdout)
        return 0

    rules = load_rules(project_dir)
    if not rules:
        json.dump({"continue": True}, sys.stdout)
        return 0

    matcher = PatternMatcher(rules)
    matches = matcher.scan(prompt, "llm")
    audit_timeouts("UserPromptExpansion", matcher.last_timeouts, project_dir=project_dir)
    if not matches:
        json.dump({"continue": True}, sys.stdout)
        return 0

    result = apply_actions(prompt, matches, project_dir)

    if result.warn_reasons:
        emit_warnings(result.warn_reasons)
    audit_matches(
        "UserPromptExpansion",
        "warn",
        [m for m in matches if m.rule.action == "warn"],
        project_dir=project_dir,
    )

    if result.block_reasons:
        audit_matches(
            "UserPromptExpansion",
            "block",
            [m for m in matches if m.rule.action == "block"],
            project_dir=project_dir,
        )
        json.dump(
            build_decision_block_response("UserPromptExpansion", result.block_reasons),
            sys.stdout,
        )
        sys.stderr.write(f"Slash-command expansion blocked: {'; '.join(result.block_reasons)}\n")
        return 0

    # No `updatedInput` available -- mirror UserPromptSubmit's redact-skipped
    # path so the model knows matched content is sensitive.
    redact_matches = [m for m in matches if m.rule.action == "redact"]
    if redact_matches:
        ids = sorted({m.rule.id for m in redact_matches})
        sys.stderr.write(f"Warning: redact rules {ids} cannot modify slash-command expansions\n")
        audit_matches(
            "UserPromptExpansion", "redact-skipped", redact_matches, project_dir=project_dir
        )
        redact_response: dict[str, Any] = {
            "continue": True,
            "hookSpecificOutput": {
                "hookEventName": "UserPromptExpansion",
                "additionalContext": (
                    f"Redaction hook: rules {ids} matched the expanded slash-command "
                    "prompt but cannot rewrite it. Treat any matched content as "
                    "sensitive and do not echo it back."
                ),
            },
        }
        json.dump(redact_response, sys.stdout)
        return 0

    json.dump({"continue": True}, sys.stdout)
    return 0
