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


def test_post_tool_use_redacts_via_updated_tool_output(rules_dir: Path) -> None:
    """Test PostToolUse redacts output via hookSpecificOutput.updatedToolOutput."""
    from redaction_hooks.hooks import handle_post_tool_use

    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_response": {"content": "contact: alice@secret.com"},
    }
    code, output = capture_output(handle_post_tool_use, data, rules_dir)
    assert code == 0
    updated = output["hookSpecificOutput"]["updatedToolOutput"]
    assert "alice@secret.com" not in updated["content"]
    assert "@example.com" in updated["content"]
    assert output["hookSpecificOutput"]["hookEventName"] == "PostToolUse"


def test_post_tool_use_redacts_bash_stdout_and_stderr(tmp_path: Path) -> None:
    """Test PostToolUse independently redacts each Bash output field."""
    from redaction_hooks.hooks import handle_post_tool_use

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: email-redact
    pattern: '[a-z]+@secret\\.com'
    action: redact
    replacement: email
    target: tool
""")
    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_response": {
            "stdout": "user: alice@secret.com",
            "stderr": "warning: bob@secret.com not found",
            "interrupted": False,
        },
    }
    code, output = capture_output(handle_post_tool_use, data, tmp_path)
    assert code == 0
    updated = output["hookSpecificOutput"]["updatedToolOutput"]
    assert "alice@secret.com" not in updated["stdout"]
    assert "bob@secret.com" not in updated["stderr"]
    assert updated["interrupted"] is False  # untouched fields preserved


def test_post_tool_use_redacts_grep_matches_list(tmp_path: Path) -> None:
    """Test PostToolUse redacts each element of a Grep matches list independently."""
    from redaction_hooks.hooks import handle_post_tool_use

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: email-redact
    pattern: '[a-z]+@secret\\.com'
    action: redact
    replacement: email
    target: tool
""")
    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Grep",
        "tool_response": {
            "matches": [
                "line1: alice@secret.com",
                "line2: clean",
                "line3: bob@secret.com",
            ],
        },
    }
    code, output = capture_output(handle_post_tool_use, data, tmp_path)
    assert code == 0
    matches = output["hookSpecificOutput"]["updatedToolOutput"]["matches"]
    assert "alice@secret.com" not in matches[0]
    assert matches[1] == "line2: clean"
    assert "bob@secret.com" not in matches[2]


def test_post_tool_use_redaction_consistent_across_fields(tmp_path: Path) -> None:
    """Test the same secret in two fields gets the same replacement (mapping store)."""
    from redaction_hooks.hooks import handle_post_tool_use

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: email-redact
    pattern: '[a-z]+@secret\\.com'
    action: redact
    replacement: email
    target: tool
""")
    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_response": {
            "stdout": "user: alice@secret.com",
            "stderr": "user: alice@secret.com again",
        },
    }
    code, output = capture_output(handle_post_tool_use, data, tmp_path)
    assert code == 0
    updated = output["hookSpecificOutput"]["updatedToolOutput"]
    import re as _re

    stdout_repl = _re.search(r"redacted-[0-9a-f]+@example\.com", updated["stdout"])
    stderr_repl = _re.search(r"redacted-[0-9a-f]+@example\.com", updated["stderr"])
    assert stdout_repl and stderr_repl
    assert stdout_repl.group(0) == stderr_repl.group(0)


def test_post_tool_use_block_wins_over_redact(tmp_path: Path) -> None:
    """Test PostToolUse blocks when block and redact rules both match across fields."""
    from redaction_hooks.hooks import handle_post_tool_use

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-block
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
    target: tool
  - id: email-redact
    pattern: '[a-z]+@secret\\.com'
    action: redact
    replacement: email
    target: tool
""")
    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_response": {
            "stdout": "key=AKIAIOSFODNN7EXAMPLE",
            "stderr": "user: alice@secret.com",
        },
    }
    code, output = capture_output(handle_post_tool_use, data, tmp_path)
    assert code == 2
    assert output["decision"] == "block"
    assert "aws-block" in output["reason"]
    assert "updatedToolOutput" not in output["hookSpecificOutput"]


def test_post_tool_use_warn_only_emits_warning_no_update(tmp_path: Path) -> None:
    """Test PostToolUse warn-only matches emit warning but no updatedToolOutput."""
    from redaction_hooks.hooks import handle_post_tool_use

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: warn-rule
    pattern: 'sensitive'
    action: warn
    target: tool
""")
    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_response": {"content": "this is sensitive data"},
    }
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        code, output = capture_output(handle_post_tool_use, data, tmp_path)
    assert code == 0
    assert output == {"continue": True}
    assert "warn-rule" in stderr.getvalue()


def test_post_tool_use_non_dict_response_warns(tmp_path: Path) -> None:
    """Test PostToolUse with string-shaped tool_response cannot redact safely."""
    from redaction_hooks.hooks import handle_post_tool_use

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: email-redact
    pattern: '[a-z]+@secret\\.com'
    action: redact
    replacement: email
    target: tool
""")
    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "CustomTool",
        "tool_response": "contact: alice@secret.com",
    }
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        code, output = capture_output(handle_post_tool_use, data, tmp_path)
    assert code == 0
    assert output == {"continue": True}
    assert "cannot redact non-dict" in stderr.getvalue()


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


# Tests for audit-log integration


def test_audit_logged_on_pre_tool_use_block(rules_dir: Path) -> None:
    """A blocked PreToolUse event writes a 'block' entry to the audit log."""
    from redaction_hooks.audit import read_entries

    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"content": "AKIAIOSFODNN7EXAMPLE", "file_path": "x.py"},
    }
    capture_output(handle_pre_tool_use, data, rules_dir)
    entries = read_entries(rules_dir)
    blocks = [e for e in entries if e["action"] == "block"]
    assert blocks
    assert blocks[-1]["hook"] == "PreToolUse"
    assert "aws-key" in blocks[-1]["rule_ids"]
    assert blocks[-1]["tool"] == "Write"


def test_audit_logged_on_user_prompt_submit_block(rules_dir: Path) -> None:
    """A blocked UserPromptSubmit event writes a 'block' entry."""
    from redaction_hooks.audit import read_entries

    data = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "my key is AKIAIOSFODNN7EXAMPLE",
    }
    capture_output(handle_user_prompt_submit, data, rules_dir)
    entries = read_entries(rules_dir)
    blocks = [e for e in entries if e["action"] == "block" and e["hook"] == "UserPromptSubmit"]
    assert blocks
    assert "aws-key" in blocks[0]["rule_ids"]


def test_audit_logged_on_post_tool_use_redact(rules_dir: Path) -> None:
    """A PostToolUse redact event writes a 'redact' entry."""
    from redaction_hooks.audit import read_entries
    from redaction_hooks.hooks import handle_post_tool_use

    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_response": {"content": "contact: alice@secret.com"},
    }
    capture_output(handle_post_tool_use, data, rules_dir)
    entries = read_entries(rules_dir)
    redacts = [e for e in entries if e["action"] == "redact" and e["hook"] == "PostToolUse"]
    assert redacts
    assert "email" in redacts[0]["rule_ids"]


def test_audit_not_written_when_no_match(rules_dir: Path) -> None:
    """A clean tool input writes no audit entry."""
    from redaction_hooks.audit import read_entries

    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"content": "nothing sensitive", "file_path": "x.py"},
    }
    capture_output(handle_pre_tool_use, data, rules_dir)
    assert read_entries(rules_dir) == []


# Tests for file_content_pattern feature


def test_file_content_blocks_read_with_matching_content(tmp_path: Path) -> None:
    """Test file_content_pattern blocks Read when file contains matching pattern."""
    # Create target file with proprietary header
    target = tmp_path / "secret.txt"
    target.write_text("PROPRIETARY AND CONFIDENTIAL\nThis is secret content.")

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: block-proprietary
    file_content_pattern: 'PROPRIETARY AND CONFIDENTIAL'
    file_tools: read
    action: block
""")
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(target)},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 2
    assert output["continue"] is False
    assert "block-proprietary" in output["hookSpecificOutput"]["permissionDecisionReason"]


def test_file_content_allows_read_without_matching_content(tmp_path: Path) -> None:
    """Test file_content_pattern allows Read when file doesn't contain pattern."""
    target = tmp_path / "public.txt"
    target.write_text("This is public content.\nNo secrets here.")

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: block-proprietary
    file_content_pattern: 'PROPRIETARY AND CONFIDENTIAL'
    file_tools: read
    action: block
""")
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(target)},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 0
    assert output["continue"] is True


def test_file_content_blocks_edit_with_file_tools_write(tmp_path: Path) -> None:
    """Test file_content_pattern with file_tools=write blocks Edit tool."""
    target = tmp_path / "generated.py"
    target.write_text("# DO NOT EDIT - auto generated\ncode = 42")

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: block-generated
    file_content_pattern: 'DO NOT EDIT'
    file_tools: write
    action: block
""")
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {"file_path": str(target), "old_string": "42", "new_string": "43"},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 2
    assert output["continue"] is False


def test_file_content_allows_read_with_file_tools_write(tmp_path: Path) -> None:
    """Test file_content_pattern with file_tools=write allows Read tool."""
    target = tmp_path / "generated.py"
    target.write_text("# DO NOT EDIT - auto generated\ncode = 42")

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: block-generated
    file_content_pattern: 'DO NOT EDIT'
    file_tools: write
    action: block
""")
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(target)},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 0
    assert output["continue"] is True


def test_file_content_rw_blocks_both_read_and_write(tmp_path: Path) -> None:
    """Test file_tools=rw blocks both Read and Write/Edit tools."""
    target = tmp_path / "secret.yaml"
    target.write_text("kind: Secret\ndata: abc123")

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: block-k8s-secret
    file_content_pattern: 'kind:\\s*Secret'
    file_tools: rw
    action: block
""")
    # Read blocked
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(target)},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 2

    # Edit blocked
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {"file_path": str(target), "old_string": "abc", "new_string": "xyz"},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 2


def test_file_content_unreadable_file_blocks(tmp_path: Path) -> None:
    """Test that unreadable file blocks when file_content rule exists."""
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: block-proprietary
    file_content_pattern: 'PROPRIETARY'
    file_tools: read
    action: block
""")
    # Non-existent file
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(tmp_path / "nonexistent.txt")},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 2
    assert "Cannot read file" in output["hookSpecificOutput"]["permissionDecisionReason"]


def test_file_content_combined_with_path_pattern(tmp_path: Path) -> None:
    """Test file_content_pattern combined with path_pattern."""
    target = tmp_path / "config.yaml"
    target.write_text("kind: Secret\ndata: password123")

    other = tmp_path / "config.json"
    other.write_text("kind: Secret\ndata: password123")

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: block-yaml-secret
    path_pattern: '*.yaml'
    file_content_pattern: 'kind:\\s*Secret'
    file_tools: rw
    action: block
""")
    # YAML with Secret: blocked
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(target)},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 2

    # JSON with same content: allowed (path doesn't match)
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(other)},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 0


def test_file_content_only_checks_first_100_lines(tmp_path: Path) -> None:
    """Test that file_content_pattern only checks first 100 lines."""
    # Create file with secret on line 101
    lines = ["safe content\n"] * 100 + ["PROPRIETARY AND CONFIDENTIAL\n"]
    target = tmp_path / "bigfile.txt"
    target.write_text("".join(lines))

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: block-proprietary
    file_content_pattern: 'PROPRIETARY AND CONFIDENTIAL'
    file_tools: read
    action: block
""")
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(target)},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    # Should NOT block because secret is on line 101
    assert code == 0
    assert output["continue"] is True


def test_file_content_blocks_within_first_100_lines(tmp_path: Path) -> None:
    """Test that file_content_pattern blocks when pattern is within first 100 lines."""
    # Create file with secret on line 50
    lines = ["safe content\n"] * 49 + ["PROPRIETARY AND CONFIDENTIAL\n"] + ["more safe\n"] * 50
    target = tmp_path / "bigfile.txt"
    target.write_text("".join(lines))

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: block-proprietary
    file_content_pattern: 'PROPRIETARY AND CONFIDENTIAL'
    file_tools: read
    action: block
""")
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(target)},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 2
    assert output["continue"] is False


def test_file_content_warn_action(tmp_path: Path) -> None:
    """Test file_content_pattern with warn action."""
    target = tmp_path / "warning.txt"
    target.write_text("This file contains SENSITIVE information")

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: warn-sensitive
    file_content_pattern: 'SENSITIVE'
    file_tools: rw
    action: warn
""")
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(target)},
    }
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 0
    assert output["continue"] is True
    assert "Warning" in stderr.getvalue()
    assert "warn-sensitive" in stderr.getvalue()


def test_file_content_ignores_non_file_tools(tmp_path: Path) -> None:
    """Test file_content_pattern does not apply to non-file tools like Bash."""
    target = tmp_path / "secret.sh"
    target.write_text("PROPRIETARY AND CONFIDENTIAL\necho hello")

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: block-proprietary
    file_content_pattern: 'PROPRIETARY AND CONFIDENTIAL'
    action: block
""")
    # Bash command mentioning the file (not Read/Write/Edit)
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": f"cat {target}"},
    }
    # Should be allowed - file_content rules don't apply to Bash tool execution
    # (even though path is extracted, file_tools filter excludes Bash)
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 0
    assert output["continue"] is True


# Tests for path-traversal / symlink hardening (#4)


def test_file_content_blocks_absolute_path_outside_project(tmp_path: Path) -> None:
    """A file_content rule must refuse to scan files resolving outside project_dir."""
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: block-proprietary
    file_content_pattern: 'PROPRIETARY'
    file_tools: read
    action: warn
""")
    # /etc/hostname exists on Linux and is outside tmp_path
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/etc/hostname"},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    # Even with warn-action, outside-project blocks (refuse to assess)
    assert code == 2
    assert "outside project boundary" in output["hookSpecificOutput"]["permissionDecisionReason"]


def test_file_content_blocks_symlink_pointing_outside(tmp_path: Path) -> None:
    """A symlink inside project pointing outside is rejected after resolve()."""
    link = tmp_path / "looks-local.txt"
    link.symlink_to("/etc/hostname")

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: warn-anything
    file_content_pattern: '.'
    file_tools: read
    action: warn
""")
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(link)},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 2
    assert "outside project boundary" in output["hookSpecificOutput"]["permissionDecisionReason"]


def test_file_content_allows_path_inside_project(tmp_path: Path) -> None:
    """Sanity: paths inside project are still scanned normally."""
    target = tmp_path / "ok.txt"
    target.write_text("nothing special here")
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: warn-anything
    file_content_pattern: '.'
    file_tools: read
    action: warn
""")
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(target)},
    }
    code, output = capture_output(handle_pre_tool_use, data, tmp_path)
    assert code == 0


# Tests for _extract_bash_paths


def test_bash_paths_compound_command(tmp_path: Path) -> None:
    """Each subcommand in a compound bash command is tokenized independently."""
    from redaction_hooks.hooks import _extract_bash_paths

    paths = _extract_bash_paths("cd /tmp && cat /etc/hosts || rm /var/log/x")
    assert "/tmp" in paths
    assert "/etc/hosts" in paths
    assert "/var/log/x" in paths
    assert "&&" not in paths
    assert "||" not in paths


def test_bash_paths_handles_pipe_and_semicolons(tmp_path: Path) -> None:
    """Commands joined by | or ; are split into independent subcommands."""
    from redaction_hooks.hooks import _extract_bash_paths

    paths = _extract_bash_paths("cat /etc/hosts | grep foo ; head /etc/passwd")
    assert "/etc/hosts" in paths
    assert "/etc/passwd" in paths
    assert "foo" not in paths


def test_bash_paths_extracts_value_from_flag_assignment(tmp_path: Path) -> None:
    """`--key=value` contributes the value, not the whole `--key=value` token."""
    from redaction_hooks.hooks import _extract_bash_paths

    paths = _extract_bash_paths("cmd --output=/tmp/out --dir=/var/log -o=/tmp/x")
    assert "/tmp/out" in paths
    assert "/var/log" in paths
    assert "/tmp/x" in paths
    assert "--output=/tmp/out" not in paths


def test_bash_paths_skips_bare_flags(tmp_path: Path) -> None:
    """Flags without `=` are not extracted as paths."""
    from redaction_hooks.hooks import _extract_bash_paths

    paths = _extract_bash_paths("git commit --no-verify -m 'msg'")
    assert "--no-verify" not in paths
    assert "-m" not in paths
    # `msg` has no /. and is not a flag -> not a path
    assert "msg" not in paths


def test_bash_paths_skips_non_path_tokens(tmp_path: Path) -> None:
    """Tokens that look like config values, not paths, are not extracted."""
    from redaction_hooks.hooks import _extract_bash_paths

    paths = _extract_bash_paths("git config user.email alice@example.com")
    assert "alice@example.com" not in paths
    assert "user.email" not in paths
    assert "config" not in paths


def test_bash_paths_url_in_flag_value_skipped(tmp_path: Path) -> None:
    """A URL embedded in `--key=URL` is not classified as a path."""
    from redaction_hooks.hooks import _extract_bash_paths

    paths = _extract_bash_paths("curl --url=https://example.com -o /tmp/x")
    assert "/tmp/x" in paths
    assert not any(p.startswith("http") for p in paths)


def test_bash_paths_falls_back_on_unbalanced_quotes(tmp_path: Path) -> None:
    """Malformed (unclosed) shell input still yields paths via regex fallback."""
    from redaction_hooks.hooks import _extract_bash_paths

    paths = _extract_bash_paths("cat /etc/passwd 'unterminated")  # unclosed quote
    assert any("/etc/passwd" in p for p in paths)


# Tests for PathMatcher resolve-warning


def test_path_matcher_warns_on_resolve_failure(tmp_path: Path) -> None:
    """A transient OSError from Path.resolve() emits a stderr warning."""
    from unittest.mock import patch

    from redaction_hooks.models import Rule
    from redaction_hooks.path_matcher import PathMatcher

    rule = Rule(id="r", path_pattern="/anywhere/*", action="block")
    matcher = PathMatcher([rule], tmp_path)
    stderr = io.StringIO()
    with (
        patch("pathlib.Path.resolve", side_effect=OSError("simulated FS error")),
        patch.object(sys, "stderr", stderr),
    ):
        matcher.scan(["/anywhere/x"], "tool", "Read")
    assert "cannot resolve" in stderr.getvalue()
