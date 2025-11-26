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
import sys
from pathlib import Path
from typing import Any

from .actions import apply_actions
from .config import load_rules
from .matcher import PatternMatcher


def _get_tool_input_content(tool_name: str, tool_input: dict[str, Any]) -> str | None:
    """Extract content to scan from tool input based on tool type."""
    if tool_name in ("Write", "Edit", "MultiEdit"):
        return tool_input.get("content") or tool_input.get("new_string")
    if tool_name == "Bash":
        return tool_input.get("command")
    if tool_name == "Read":
        return tool_input.get("file_path")
    return None


def _get_tool_output_content(tool_name: str, tool_response: Any) -> str | None:
    """Extract content to scan from tool output based on tool type."""
    if not isinstance(tool_response, dict):
        return str(tool_response) if tool_response else None

    # Read tool returns file content
    if tool_name == "Read":
        return tool_response.get("content") or tool_response.get("output")

    # Bash tool returns stdout/stderr
    if tool_name == "Bash":
        parts = []
        if tool_response.get("stdout"):
            parts.append(tool_response["stdout"])
        if tool_response.get("stderr"):
            parts.append(tool_response["stderr"])
        if tool_response.get("output"):
            parts.append(tool_response["output"])
        return "\n".join(parts) if parts else None

    # Grep/Glob return matches
    if tool_name in ("Grep", "Glob"):
        if "matches" in tool_response:
            return "\n".join(str(m) for m in tool_response["matches"])
        return tool_response.get("output")

    # WebFetch returns content
    if tool_name == "WebFetch":
        return tool_response.get("content") or tool_response.get("output")

    # Generic fallback - try common fields
    for field in ("content", "output", "result", "text"):
        if field in tool_response:
            return str(tool_response[field])

    return None


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
    original_input: dict[str, Any], redacted_content: str, tool_name: str
) -> dict[str, Any]:
    """Build a response with redacted content."""
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
        },
        "continue": True,
        "systemMessage": "Content was redacted before execution",
    }


def handle_pre_tool_use(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle PreToolUse hook event."""
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    content = _get_tool_input_content(tool_name, tool_input)
    if not content:
        json.dump({"continue": True}, sys.stdout)
        return 0

    rules = load_rules(project_dir)
    if not rules:
        json.dump({"continue": True}, sys.stdout)
        return 0

    matcher = PatternMatcher(rules)
    matches = matcher.scan(content, "tool")
    if not matches:
        json.dump({"continue": True}, sys.stdout)
        return 0

    result = apply_actions(content, matches, project_dir)

    if result.block_reasons:
        json.dump(_build_block_response(result.block_reasons), sys.stdout)
        sys.stderr.write(f"Blocked: {'; '.join(result.block_reasons)}\n")
        return 2

    if result.redacted_text and result.redacted_text != content:
        json.dump(_build_redact_response(tool_input, result.redacted_text, tool_name), sys.stdout)
        return 0

    json.dump({"continue": True}, sys.stdout)
    return 0


def handle_user_prompt_submit(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle UserPromptSubmit hook event."""
    prompt = data.get("prompt", "")
    if not prompt:
        json.dump({"continue": True}, sys.stdout)
        return 0

    rules = load_rules(project_dir)
    if not rules:
        json.dump({"continue": True}, sys.stdout)
        return 0

    matcher = PatternMatcher(rules)
    matches = matcher.scan(prompt, "llm")
    if not matches:
        json.dump({"continue": True}, sys.stdout)
        return 0

    result = apply_actions(prompt, matches, project_dir)

    if result.block_reasons:
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

    # Warn about redact matches - UserPromptSubmit doesn't support updatedInput
    redact_matches = [m for m in matches if m.rule.action == "redact"]
    if redact_matches:
        ids = ", ".join(m.rule.id for m in redact_matches)
        sys.stderr.write(f"Warning: redact rules [{ids}] cannot modify prompts\n")

    json.dump({"continue": True}, sys.stdout)
    return 0


def handle_post_tool_use(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle PostToolUse hook event - scan tool output for secrets.

    Note: PostToolUse cannot modify tool output, only block. Redact rules
    will trigger a warning but allow continuation.
    """
    tool_name = data.get("tool_name", "")
    tool_response = data.get("tool_response")

    content = _get_tool_output_content(tool_name, tool_response)
    if not content:
        json.dump({"continue": True}, sys.stdout)
        return 0

    rules = load_rules(project_dir)
    if not rules:
        json.dump({"continue": True}, sys.stdout)
        return 0

    matcher = PatternMatcher(rules)
    matches = matcher.scan(content, "tool")
    if not matches:
        json.dump({"continue": True}, sys.stdout)
        return 0

    # Check for blocking rules
    block_matches = [m for m in matches if m.rule.action == "block"]
    if block_matches:
        reasons = [f"{m.rule.id}: {m.rule.description or 'matched'}" for m in block_matches]
        response = {
            "decision": "block",
            "reason": f"Tool output blocked: {'; '.join(reasons)}",
            "hookSpecificOutput": {"hookEventName": "PostToolUse"},
        }
        json.dump(response, sys.stdout)
        sys.stderr.write(f"Tool output blocked: {'; '.join(reasons)}\n")
        return 2

    # Warn about redact matches - PostToolUse cannot modify output
    redact_matches = [m for m in matches if m.rule.action == "redact"]
    if redact_matches:
        ids = ", ".join(m.rule.id for m in redact_matches)
        sys.stderr.write(f"Warning: redact rules [{ids}] cannot modify tool output\n")

    json.dump({"continue": True}, sys.stdout)
    return 0


def run_hook(project_dir: Path | None = None) -> int:
    """Main hook entry point. Reads JSON from stdin, dispatches to handler."""
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"Invalid JSON input: {e}\n")
        return 1

    event = data.get("hook_event_name", "")

    if event == "PreToolUse":
        return handle_pre_tool_use(data, project_dir)
    if event == "PostToolUse":
        return handle_post_tool_use(data, project_dir)
    if event == "UserPromptSubmit":
        return handle_user_prompt_submit(data, project_dir)

    # Unknown or unsupported event, allow to continue
    json.dump({"continue": True}, sys.stdout)
    return 0
