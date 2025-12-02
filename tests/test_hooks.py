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

"""Tests for Claude Code hook handlers."""

import io
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from redaction_hooks.hooks import (
    handle_pre_tool_use,
    handle_user_prompt_submit,
    run_hook,
)


@pytest.fixture
def rules_dir(tmp_path: Path) -> Path:
    """Create a temp dir with test rules."""
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
    description: AWS Access Key

  - id: email
    pattern: '[a-z]+@secret\\.com'
    action: redact
    replacement: email
    target: tool
""")
    return tmp_path


def capture_output(func: Any, *args: Any, **kwargs: Any) -> tuple[int, dict[str, Any]]:
    """Capture stdout from a hook function and parse as JSON."""
    stdout = io.StringIO()
    with patch.object(sys, "stdout", stdout):
        result = func(*args, **kwargs)
    stdout.seek(0)
    output = json.load(stdout)
    return result, output


def test_pre_tool_use_blocks_aws_key(rules_dir: Path) -> None:
    """Test PreToolUse blocks AWS key in Write content."""
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"content": "aws_key = AKIAIOSFODNN7EXAMPLE", "file_path": "config.py"},
    }
    code, output = capture_output(handle_pre_tool_use, data, rules_dir)
    assert code == 2
    assert output["continue"] is False
    assert "deny" in output["hookSpecificOutput"]["permissionDecision"]


def test_pre_tool_use_blocks_bash_command(rules_dir: Path) -> None:
    """Test PreToolUse blocks AWS key in Bash command."""
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "export AWS_KEY=AKIAIOSFODNN7EXAMPLE"},
    }
    code, output = capture_output(handle_pre_tool_use, data, rules_dir)
    assert code == 2
    assert output["continue"] is False


def test_pre_tool_use_redacts_email(rules_dir: Path) -> None:
    """Test PreToolUse redacts email in tool content."""
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"content": "contact: alice@secret.com", "file_path": "info.txt"},
    }
    code, output = capture_output(handle_pre_tool_use, data, rules_dir)
    assert code == 0
    assert output["continue"] is True
    updated = output["hookSpecificOutput"]["updatedInput"]["content"]
    assert "alice@secret.com" not in updated
    assert "@example.com" in updated


def test_pre_tool_use_allows_clean_content(rules_dir: Path) -> None:
    """Test PreToolUse allows content without matches."""
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"content": "clean content here", "file_path": "test.txt"},
    }
    code, output = capture_output(handle_pre_tool_use, data, rules_dir)
    assert code == 0
    assert output["continue"] is True


def test_user_prompt_blocks_secret(rules_dir: Path) -> None:
    """Test UserPromptSubmit blocks prompt with AWS key."""
    data = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Use this key: AKIAIOSFODNN7EXAMPLE",
    }
    code, output = capture_output(handle_user_prompt_submit, data, rules_dir)
    assert code == 2
    assert output["decision"] == "block"


def test_user_prompt_allows_clean(rules_dir: Path) -> None:
    """Test UserPromptSubmit allows clean prompt."""
    data = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Hello, please help me",
    }
    code, output = capture_output(handle_user_prompt_submit, data, rules_dir)
    assert code == 0
    assert output["continue"] is True


def test_run_hook_dispatches_pre_tool_use(rules_dir: Path) -> None:
    """Test run_hook dispatches to PreToolUse handler."""
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"content": "clean"},
    }
    stdin = io.StringIO(json.dumps(data))
    stdout = io.StringIO()
    with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout):
        code = run_hook(rules_dir)
    assert code == 0


def test_run_hook_unknown_event(rules_dir: Path) -> None:
    """Test run_hook handles unknown events gracefully."""
    data = {"hook_event_name": "UnknownEvent"}
    stdin = io.StringIO(json.dumps(data))
    stdout = io.StringIO()
    with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout):
        code = run_hook(rules_dir)
    assert code == 0
    stdout.seek(0)
    output = json.load(stdout)
    assert output["continue"] is True


def test_run_hook_invalid_json(rules_dir: Path) -> None:
    """Test run_hook handles invalid JSON input."""
    stdin = io.StringIO("not json")
    stderr = io.StringIO()
    with patch.object(sys, "stdin", stdin), patch.object(sys, "stderr", stderr):
        code = run_hook(rules_dir)
    assert code == 1


def test_no_rules_allows_all(tmp_path: Path) -> None:
    """Test that missing rules file allows all content."""
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"content": "AKIAIOSFODNN7EXAMPLE"},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 0
    assert output["continue"] is True


def test_user_prompt_redact_warns(tmp_path: Path) -> None:
    """Test that redact rules on prompts warn but allow."""
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: email-redact
    pattern: '[a-z]+@test\\.com'
    action: redact
    replacement: email
    target: llm
""")
    data = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Contact alice@test.com please",
    }
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        code, output = capture_output(handle_user_prompt_submit, data, tmp_path)
    assert code == 0
    assert output["continue"] is True
    assert "Warning" in stderr.getvalue()
    assert "email-redact" in stderr.getvalue()


def test_post_tool_use_blocks_secret_in_read_output(rules_dir: Path) -> None:
    """Test PostToolUse blocks AWS key in Read tool output."""
    from redaction_hooks.hooks import handle_post_tool_use

    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_response": {"content": "aws_key = AKIAIOSFODNN7EXAMPLE"},
    }
    code, output = capture_output(handle_post_tool_use, data, rules_dir)
    assert code == 2
    assert output["decision"] == "block"
    assert "aws-key" in output["reason"]


def test_post_tool_use_blocks_secret_in_bash_output(rules_dir: Path) -> None:
    """Test PostToolUse blocks AWS key in Bash tool output."""
    from redaction_hooks.hooks import handle_post_tool_use

    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_response": {"stdout": "AWS_KEY=AKIAIOSFODNN7EXAMPLE"},
    }
    code, output = capture_output(handle_post_tool_use, data, rules_dir)
    assert code == 2
    assert output["decision"] == "block"


def test_post_tool_use_allows_clean_output(rules_dir: Path) -> None:
    """Test PostToolUse allows clean tool output."""
    from redaction_hooks.hooks import handle_post_tool_use

    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_response": {"content": "clean content here"},
    }
    code, output = capture_output(handle_post_tool_use, data, rules_dir)
    assert code == 0
    assert output["continue"] is True


def test_post_tool_use_redact_warns(rules_dir: Path) -> None:
    """Test PostToolUse warns for redact rules (cannot modify output)."""
    from redaction_hooks.hooks import handle_post_tool_use

    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_response": {"content": "contact: alice@secret.com"},
    }
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        code, output = capture_output(handle_post_tool_use, data, rules_dir)
    assert code == 0
    assert output["continue"] is True
    assert "Warning" in stderr.getvalue()
    assert "email" in stderr.getvalue()


def test_run_hook_dispatches_post_tool_use(rules_dir: Path) -> None:
    """Test run_hook dispatches to PostToolUse handler."""
    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_response": {"content": "clean"},
    }
    stdin = io.StringIO(json.dumps(data))
    stdout = io.StringIO()
    with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout):
        code = run_hook(rules_dir)
    assert code == 0


def test_tool_filter_blocks_only_matching_tool(tmp_path: Path) -> None:
    """Test that tool-specific rules only trigger for that tool."""
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: no-verify
    pattern: '--no-verify'
    action: block
    tool: Bash
    description: Bypasses hooks
""")
    # Bash command with --no-verify: blocked
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git commit --no-verify"},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 2
    assert output["continue"] is False

    # Write with --no-verify in content: allowed (wrong tool)
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"content": "git commit --no-verify", "file_path": "test.sh"},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 0
    assert output["continue"] is True


def test_warn_action_allows_but_logs(tmp_path: Path) -> None:
    """Test that warn action allows the operation but logs to stderr."""
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: warn-tmp
    path_pattern: '/tmp/*'
    action: warn
    description: Writing to tmp directory
""")
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"content": "test data", "file_path": "/tmp/test.txt"},
    }
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 0
    assert output["continue"] is True
    assert "Warning" in stderr.getvalue()
    assert "warn-tmp" in stderr.getvalue()


def test_path_pattern_blocks_env_file(tmp_path: Path) -> None:
    """Test that path_pattern blocks access to .env files."""
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: block-env
    path_pattern: '*.env'
    action: block
    tool: Read
    description: Blocked .env file
""")
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/home/user/.env"},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 2
    assert output["continue"] is False
    assert "block-env" in output["hookSpecificOutput"]["permissionDecisionReason"]


def test_path_pattern_allows_non_matching_file(tmp_path: Path) -> None:
    """Test that path_pattern allows files that don't match."""
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: block-env
    path_pattern: '*.env'
    action: block
""")
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/home/user/config.yaml"},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 0
    assert output["continue"] is True


def test_combined_path_and_pattern_requires_both(tmp_path: Path) -> None:
    """Test that combined rules require both path AND pattern to match."""
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-in-env
    path_pattern: '*.env'
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
    description: AWS key in env file
""")
    # AWS key in .env file: blocked
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"content": "AWS_KEY=AKIAIOSFODNN7EXAMPLE", "file_path": "config.env"},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 2
    assert output["continue"] is False

    # AWS key in non-.env file: allowed (path doesn't match)
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"content": "AWS_KEY=AKIAIOSFODNN7EXAMPLE", "file_path": "config.yaml"},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 0
    assert output["continue"] is True

    # Clean content in .env file: allowed (pattern doesn't match)
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"content": "DEBUG=true", "file_path": "config.env"},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 0
    assert output["continue"] is True


def test_bash_path_extraction_blocks(tmp_path: Path) -> None:
    """Test that paths in Bash commands are extracted and matched."""
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: block-etc
    path_pattern: '/etc/*'
    action: block
    tool: Bash
    description: Blocked /etc access
""")
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "cat /etc/passwd"},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 2
    assert output["continue"] is False


def test_bash_path_extraction_with_rm(tmp_path: Path) -> None:
    """Test that rm commands with paths are blocked appropriately."""
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: block-rm-home
    path_pattern: '/home/*'
    pattern: 'rm\\s+.*-r'
    action: block
    tool: Bash
    description: Dangerous rm in /home
""")
    # rm -rf on /home path: blocked
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /home/user/data"},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 2

    # rm -rf on /tmp path: allowed (different path)
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /tmp/cache"},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 0


def test_bash_url_not_matched_as_path(tmp_path: Path) -> None:
    """Test that URLs in Bash commands are not treated as paths."""
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: block-http
    path_pattern: 'http*'
    action: block
    tool: Bash
""")
    # URL should not trigger path-based blocking
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "curl https://example.com/api"},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 0
    assert output["continue"] is True
