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

"""Stop / SubagentStop handler.

Both events fire after the message is on the wire, so this is observe-only.
Redact-action matches surface as redact-skipped audits.
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
from ._common import audit_matches, audit_timeouts


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
    return "\n".join(walk_strings(last)), None


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
        audit_missing_key(
            hook_event, "last_assistant_message|transcript_path", project_dir=project_dir
        )
        json.dump({"continue": True}, sys.stdout)
        return 0

    if not text:
        json.dump({"continue": True}, sys.stdout)
        return 0

    matcher = PatternMatcher(llm_rules)
    matches = matcher.scan(text, "llm")
    audit_timeouts(hook_event, matcher.last_timeouts, project_dir=project_dir)
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
            audit_matches(hook_event, audit_action, action_matches, project_dir=project_dir)
    json.dump({"continue": True}, sys.stdout)
    return 0
