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
    # The model should be told a redaction occurred (rule IDs only, no secret text).
    add_ctx = output["hookSpecificOutput"]["additionalContext"]
    assert "email" in add_ctx
    assert "alice@secret.com" not in add_ctx


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
    """Test that redact rules on prompts warn but allow, and surface additionalContext."""
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
    add_ctx = output["hookSpecificOutput"]["additionalContext"]
    assert "email-redact" in add_ctx
    assert "alice@test.com" not in add_ctx
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


def test_post_tool_use_blocks_secret_in_real_read_shape(rules_dir: Path) -> None:
    """Real CC Read tool_response shape: {type, file: {content, filePath, ...}}.

    The content lives at `tool_response.file.content`, not at top level.
    """
    from redaction_hooks.hooks import handle_post_tool_use

    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_response": {
            "type": "text",
            "file": {
                "filePath": "/tmp/sample.txt",
                "content": "aws_key = AKIAIOSFODNN7EXAMPLE\n",
                "numLines": 1,
                "startLine": 1,
                "totalLines": 1,
            },
        },
    }
    code, output = capture_output(handle_post_tool_use, data, rules_dir)
    assert code == 2
    assert output["decision"] == "block"
    assert "aws-key" in output["reason"]


def test_post_tool_use_redacts_in_real_read_shape(rules_dir: Path) -> None:
    """Redact rewrite preserves the nested {file: {content}} shape."""
    from redaction_hooks.hooks import handle_post_tool_use

    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_response": {
            "type": "text",
            "file": {
                "filePath": "/tmp/sample.txt",
                "content": "contact: alice@secret.com",
                "numLines": 1,
                "startLine": 1,
                "totalLines": 1,
            },
        },
    }
    code, output = capture_output(handle_post_tool_use, data, rules_dir)
    assert code == 0
    updated = output["hookSpecificOutput"]["updatedToolOutput"]
    # The rewrite must land in the nested file.content -- not at top level.
    assert "alice@secret.com" not in updated["file"]["content"]
    assert "@example.com" in updated["file"]["content"]
    assert updated["type"] == "text"  # sibling fields preserved
    assert updated["file"]["filePath"] == "/tmp/sample.txt"
    assert updated["file"]["numLines"] == 1


def test_post_tool_use_blocks_spilled_output_file(tmp_path: Path) -> None:
    """A spill stub ({file_path, preview, ...}) is scanned by reading the file."""
    from redaction_hooks.hooks import handle_post_tool_use

    spill = tmp_path / "spilled.txt"
    spill.write_text("user data\nAKIAIOSFODNN7EXAMPLE\nmore data\n")
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
    target: tool
""")
    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_response": {
            "file_path": str(spill),
            "preview": "user data\n... (output truncated)",
            "byte_size": spill.stat().st_size,
            "truncated": True,
        },
    }
    code, output = capture_output(handle_post_tool_use, data, tmp_path)
    assert code == 2
    assert output["decision"] == "block"
    assert "aws-key" in output["reason"]


def test_post_tool_use_warns_redact_match_in_spilled(tmp_path: Path) -> None:
    """Redact rules in spilled-output content emit a redact-skipped audit entry."""
    from redaction_hooks.audit import read_entries
    from redaction_hooks.hooks import handle_post_tool_use

    spill = tmp_path / "spilled.txt"
    spill.write_text("contact alice@secret.com please\n")
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
            "file_path": str(spill),
            "preview": "contact alice@secret.com please",
            "truncated": True,
        },
    }
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        code, output = capture_output(handle_post_tool_use, data, tmp_path)
    assert code == 0
    assert output == {"continue": True}
    assert "non-redactable" in stderr.getvalue()
    skipped = [
        e
        for e in read_entries(tmp_path)
        if e["hook"] == "PostToolUse" and e["action"] == "redact-skipped"
    ]
    assert skipped
    assert "email-redact" in skipped[0]["rule_ids"]


def test_post_tool_use_unreadable_spilled_file_warns(tmp_path: Path) -> None:
    """A spill stub pointing at a missing file emits stderr and allows."""
    from redaction_hooks.hooks import handle_post_tool_use

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
    target: tool
""")
    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_response": {
            "file_path": str(tmp_path / "nonexistent.txt"),
            "preview": "",
            "truncated": True,
        },
    }
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        code, output = capture_output(handle_post_tool_use, data, tmp_path)
    assert code == 0
    assert "cannot read spilled output" in stderr.getvalue()


def test_post_tool_use_recursive_fallback_blocks_unknown_shape(tmp_path: Path) -> None:
    """Unknown dict shapes fall back to a recursive walk so secrets still match."""
    from redaction_hooks.hooks import handle_post_tool_use

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
    target: tool
""")
    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__custom__weird_tool",
        "tool_response": {
            "data": {"nested": {"value": "leaked AKIAIOSFODNN7EXAMPLE here"}},
        },
    }
    code, output = capture_output(handle_post_tool_use, data, tmp_path)
    assert code == 2
    assert output["decision"] == "block"


def test_post_tool_use_known_shape_skips_recursive_walk(tmp_path: Path) -> None:
    """A recognised tool_response shape must not trigger the recursive fallback."""
    from redaction_hooks.hooks import handle_post_tool_use

    # Bash has known fields stdout/stderr/output. A secret in `extra` (not a known
    # field) should NOT match because we recognised stdout and skipped the walk.
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
    target: tool
""")
    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_response": {
            "stdout": "ok\n",
            "extra": "AKIAIOSFODNN7EXAMPLE",  # would only match via recursive walk
        },
    }
    code, output = capture_output(handle_post_tool_use, data, tmp_path)
    assert code == 0
    assert output == {"continue": True}


def test_post_tool_use_spill_indicator_alone_required(tmp_path: Path) -> None:
    """`file_path` without any spill indicator is not treated as a spill stub."""
    from redaction_hooks.hooks import handle_post_tool_use

    spill = tmp_path / "secret.txt"
    spill.write_text("AKIAIOSFODNN7EXAMPLE\n")
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
    target: tool
""")
    # Read tool result: file_path is just a regular field, NOT a spill marker
    data = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_response": {"file_path": str(spill), "content": "(empty)"},
    }
    code, output = capture_output(handle_post_tool_use, data, tmp_path)
    # `content` field gets scanned; "(empty)" doesn't match. No spill scan.
    assert code == 0


def test_post_tool_use_failure_audits_error_match(tmp_path: Path) -> None:
    """A secret echoed back in `error` is audited (warn-only -- exit 0).

    Real CC 2.1.x failure payload uses key `error` (not `tool_error`).
    """
    from redaction_hooks.audit import read_entries
    from redaction_hooks.hooks import handle_post_tool_use_failure

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
    target: tool
""")
    data = {
        "hook_event_name": "PostToolUseFailure",
        "tool_name": "Bash",
        "tool_use_id": "toolu_failed_1",
        "tool_input": {"command": "aws s3 ls"},
        "error": "InvalidAccessKey: AKIAIOSFODNN7EXAMPLE is not valid",
        "is_interrupt": False,
        "duration_ms": 38,
    }
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        code, output = capture_output(handle_post_tool_use_failure, data, tmp_path)
    assert code == 0  # warn-only, never blocks
    assert output == {"continue": True}
    assert "aws-key" in stderr.getvalue()
    audits = [e for e in read_entries(tmp_path) if e["hook"] == "PostToolUseFailure"]
    assert audits
    assert audits[0]["tool_use_id"] == "toolu_failed_1"
    assert "aws-key" in audits[0]["rule_ids"]


def test_post_tool_use_failure_ignores_legacy_tool_error_key(tmp_path: Path) -> None:
    """Regression guard: only `error` is read, not the previous `tool_error` guess."""
    from redaction_hooks.audit import read_entries
    from redaction_hooks.hooks import handle_post_tool_use_failure

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {
        "hook_event_name": "PostToolUseFailure",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "tool_error": "AKIAIOSFODNN7EXAMPLE",  # wrong key; must NOT be scanned
    }
    code, _ = capture_output(handle_post_tool_use_failure, data, tmp_path)
    assert code == 0
    assert read_entries(tmp_path) == []


def test_post_tool_use_failure_scans_input_too(tmp_path: Path) -> None:
    """Failed-tool input is scanned in case PreToolUse missed it."""
    from redaction_hooks.hooks import handle_post_tool_use_failure

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
    target: tool
""")
    data = {
        "hook_event_name": "PostToolUseFailure",
        "tool_name": "Bash",
        "tool_input": {"command": "echo AKIAIOSFODNN7EXAMPLE && false"},
        "error": "exit code 1",
    }
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        code, _ = capture_output(handle_post_tool_use_failure, data, tmp_path)
    assert code == 0
    assert "aws-key" in stderr.getvalue()


def test_post_tool_use_failure_clean_is_no_op(tmp_path: Path) -> None:
    """No matches => no audit entry, exit 0."""
    from redaction_hooks.audit import read_entries
    from redaction_hooks.hooks import handle_post_tool_use_failure

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {
        "hook_event_name": "PostToolUseFailure",
        "tool_name": "Bash",
        "tool_input": {"command": "ls /nonexistent"},
        "error": "No such file or directory",
    }
    code, output = capture_output(handle_post_tool_use_failure, data, tmp_path)
    assert code == 0
    assert output == {"continue": True}
    assert read_entries(tmp_path) == []


def test_run_hook_dispatches_post_tool_use_failure(tmp_path: Path) -> None:
    """run_hook routes PostToolUseFailure events."""
    (tmp_path / ".redaction_rules").write_text("rules:\n  - id: x\n    pattern: x")
    data = {
        "hook_event_name": "PostToolUseFailure",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "error": "ok",
    }
    stdin = io.StringIO(json.dumps(data))
    stdout = io.StringIO()
    with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout):
        code = run_hook(tmp_path)
    assert code == 0


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


def test_audit_includes_tool_use_id_when_present(rules_dir: Path) -> None:
    """If the hook input includes `tool_use_id`, it must reach the audit entry."""
    from redaction_hooks.audit import read_entries

    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_use_id": "toolu_xyz123",
        "tool_input": {"content": "AKIAIOSFODNN7EXAMPLE", "file_path": "x.py"},
    }
    capture_output(handle_pre_tool_use, data, rules_dir)
    entries = read_entries(rules_dir)
    blocks = [e for e in entries if e["action"] == "block"]
    assert blocks
    assert blocks[-1]["tool_use_id"] == "toolu_xyz123"


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


# Tests for PreCompact handler


def _write_transcript(path: Path, *messages: dict[str, Any]) -> None:
    """Write a JSONL transcript file."""
    path.write_text("".join(json.dumps(m) + "\n" for m in messages))


def test_pre_compact_blocks_when_transcript_contains_secret(tmp_path: Path) -> None:
    """PreCompact blocks compaction if a block-action rule matches the transcript."""
    from redaction_hooks.hooks import handle_pre_compact

    transcript = tmp_path / "session.jsonl"
    _write_transcript(
        transcript,
        {"type": "user", "content": "hello"},
        {"type": "assistant", "content": "your key is AKIAIOSFODNN7EXAMPLE"},
    )
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {
        "hook_event_name": "PreCompact",
        "transcript_path": str(transcript),
        "trigger": "auto",
    }
    code, output = capture_output(handle_pre_compact, data, tmp_path)
    assert code == 2
    assert output["decision"] == "block"
    assert "aws-key" in output["reason"]
    assert "trigger=auto" in output["reason"]


def test_pre_compact_allows_clean_transcript(tmp_path: Path) -> None:
    """PreCompact allows compaction when no block rule matches."""
    from redaction_hooks.hooks import handle_pre_compact

    transcript = tmp_path / "session.jsonl"
    _write_transcript(
        transcript,
        {"type": "user", "content": "what is the weather"},
        {"type": "assistant", "content": "I cannot check the weather"},
    )
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {
        "hook_event_name": "PreCompact",
        "transcript_path": str(transcript),
        "trigger": "manual",
    }
    code, output = capture_output(handle_pre_compact, data, tmp_path)
    assert code == 0
    assert output == {"continue": True}


def test_pre_compact_warns_on_redact_rule_match(tmp_path: Path) -> None:
    """Redact rules cannot rewrite a compaction summary; warn + audit only."""
    from redaction_hooks.audit import read_entries
    from redaction_hooks.hooks import handle_pre_compact

    transcript = tmp_path / "session.jsonl"
    _write_transcript(transcript, {"type": "user", "content": "contact alice@secret.com"})
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: email-redact
    pattern: '[a-z]+@secret\\.com'
    action: redact
    replacement: email
""")
    data = {
        "hook_event_name": "PreCompact",
        "transcript_path": str(transcript),
        "trigger": "auto",
    }
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        code, output = capture_output(handle_pre_compact, data, tmp_path)
    assert code == 0
    assert output == {"continue": True}
    assert "redact rules" in stderr.getvalue()
    entries = read_entries(tmp_path)
    redacts = [e for e in entries if e["hook"] == "PreCompact" and e["action"] == "redact"]
    assert redacts


def test_pre_compact_skips_target_tool_only_rules(tmp_path: Path) -> None:
    """Rules with target=tool do not apply to PreCompact (which targets the LLM)."""
    from redaction_hooks.hooks import handle_pre_compact

    transcript = tmp_path / "session.jsonl"
    _write_transcript(transcript, {"type": "assistant", "content": "AKIAIOSFODNN7EXAMPLE"})
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-tool-only
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
    target: tool
""")
    data = {
        "hook_event_name": "PreCompact",
        "transcript_path": str(transcript),
        "trigger": "manual",
    }
    code, output = capture_output(handle_pre_compact, data, tmp_path)
    assert code == 0


def test_pre_compact_handles_unreadable_transcript(tmp_path: Path) -> None:
    """A missing or unreadable transcript_path emits stderr and allows compaction."""
    from redaction_hooks.hooks import handle_pre_compact

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {
        "hook_event_name": "PreCompact",
        "transcript_path": str(tmp_path / "nonexistent.jsonl"),
        "trigger": "auto",
    }
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        code, output = capture_output(handle_pre_compact, data, tmp_path)
    assert code == 0
    assert "cannot read transcript" in stderr.getvalue()


def test_pre_compact_skips_malformed_jsonl_lines(tmp_path: Path) -> None:
    """Malformed lines in the transcript are skipped without crashing."""
    from redaction_hooks.hooks import handle_pre_compact

    transcript = tmp_path / "session.jsonl"
    transcript.write_text(
        '{"type":"user","content":"hello"}\n'
        "this is not json\n"
        '{"type":"assistant","content":"AKIAIOSFODNN7EXAMPLE"}\n'
    )
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {
        "hook_event_name": "PreCompact",
        "transcript_path": str(transcript),
        "trigger": "manual",
    }
    code, output = capture_output(handle_pre_compact, data, tmp_path)
    assert code == 2  # still found the secret on line 3


def test_pre_compact_no_transcript_path_allows(tmp_path: Path) -> None:
    """Missing transcript_path field allows compaction (no-op)."""
    from redaction_hooks.hooks import handle_pre_compact

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {"hook_event_name": "PreCompact", "trigger": "manual"}
    code, output = capture_output(handle_pre_compact, data, tmp_path)
    assert code == 0


def test_instructions_loaded_audits_secret_in_claude_md(tmp_path: Path) -> None:
    """Loading a CLAUDE.md with a known secret pattern audits + warns."""
    from redaction_hooks.audit import read_entries
    from redaction_hooks.hooks import handle_instructions_loaded

    instr = tmp_path / "CLAUDE.md"
    instr.write_text("Important: AWS key is AKIAIOSFODNN7EXAMPLE -- do not commit\n")
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {
        "hook_event_name": "InstructionsLoaded",
        "file_path": str(instr),
        "memory_type": "Project",
        "load_reason": "session_start",
    }
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        code, output = capture_output(handle_instructions_loaded, data, tmp_path)
    assert code == 0
    assert output == {"continue": True}
    err = stderr.getvalue()
    assert "aws-key" in err
    assert "Project" in err
    assert "session_start" in err
    audits = [e for e in read_entries(tmp_path) if e["hook"] == "InstructionsLoaded"]
    assert audits
    assert audits[0]["action"] == "block"


def test_instructions_loaded_clean_no_audit(tmp_path: Path) -> None:
    """Clean instruction file produces no audit entry."""
    from redaction_hooks.audit import read_entries
    from redaction_hooks.hooks import handle_instructions_loaded

    instr = tmp_path / "CLAUDE.md"
    instr.write_text("Normal project guidance with no secrets.\n")
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {
        "hook_event_name": "InstructionsLoaded",
        "file_path": str(instr),
        "memory_type": "Project",
        "load_reason": "session_start",
    }
    code, output = capture_output(handle_instructions_loaded, data, tmp_path)
    assert code == 0
    assert read_entries(tmp_path) == []


def test_instructions_loaded_skips_target_tool_only_rules(tmp_path: Path) -> None:
    """Rules with target=tool do not apply to InstructionsLoaded (LLM-side)."""
    from redaction_hooks.audit import read_entries
    from redaction_hooks.hooks import handle_instructions_loaded

    instr = tmp_path / "CLAUDE.md"
    instr.write_text("AKIAIOSFODNN7EXAMPLE\n")
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-tool-only
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
    target: tool
""")
    data = {
        "hook_event_name": "InstructionsLoaded",
        "file_path": str(instr),
        "memory_type": "User",
        "load_reason": "session_start",
    }
    code, _ = capture_output(handle_instructions_loaded, data, tmp_path)
    assert code == 0
    assert read_entries(tmp_path) == []


def test_instructions_loaded_unreadable_file_is_no_op(tmp_path: Path) -> None:
    """A missing instruction file emits stderr and returns continue:true."""
    from redaction_hooks.hooks import handle_instructions_loaded

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {
        "hook_event_name": "InstructionsLoaded",
        "file_path": str(tmp_path / "missing.md"),
        "memory_type": "Project",
        "load_reason": "include",
    }
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        code, output = capture_output(handle_instructions_loaded, data, tmp_path)
    assert code == 0
    assert "cannot read" in stderr.getvalue()


def test_run_hook_dispatches_instructions_loaded(tmp_path: Path) -> None:
    """run_hook routes InstructionsLoaded events."""
    instr = tmp_path / "CLAUDE.md"
    instr.write_text("clean")
    (tmp_path / ".redaction_rules").write_text("rules:\n  - id: x\n    pattern: x")
    data = {
        "hook_event_name": "InstructionsLoaded",
        "file_path": str(instr),
        "memory_type": "Project",
        "load_reason": "session_start",
    }
    stdin = io.StringIO(json.dumps(data))
    stdout = io.StringIO()
    with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout):
        code = run_hook(tmp_path)
    assert code == 0


def test_stop_warns_on_secret_in_last_assistant_message(tmp_path: Path) -> None:
    """Stop scans the LAST assistant turn and warns if a rule matches."""
    from redaction_hooks.audit import read_entries
    from redaction_hooks.hooks import handle_stop

    transcript = tmp_path / "session.jsonl"
    _write_transcript(
        transcript,
        {"type": "user", "content": "hi"},
        {"type": "assistant", "content": "earlier reply"},
        {"type": "user", "content": "tell me a key"},
        {"type": "assistant", "content": "here: AKIAIOSFODNN7EXAMPLE"},
    )
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {
        "hook_event_name": "Stop",
        "transcript_path": str(transcript),
    }
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        code, output = capture_output(handle_stop, data, tmp_path)
    assert code == 0  # warn-only, never blocks
    assert output == {"continue": True}
    assert "aws-key" in stderr.getvalue()
    audits = [e for e in read_entries(tmp_path) if e["hook"] == "Stop"]
    assert audits


def test_stop_does_not_match_earlier_turns(tmp_path: Path) -> None:
    """A secret in an earlier assistant turn must NOT trigger Stop -- only the latest."""
    from redaction_hooks.audit import read_entries
    from redaction_hooks.hooks import handle_stop

    transcript = tmp_path / "session.jsonl"
    _write_transcript(
        transcript,
        {"type": "assistant", "content": "old leak: AKIAIOSFODNN7EXAMPLE"},
        {"type": "user", "content": "ok"},
        {"type": "assistant", "content": "all clean now"},
    )
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {"hook_event_name": "Stop", "transcript_path": str(transcript)}
    code, _ = capture_output(handle_stop, data, tmp_path)
    assert code == 0
    assert read_entries(tmp_path) == []


def test_subagent_stop_uses_subagentstop_hook_label(tmp_path: Path) -> None:
    """Audit entries written from SubagentStop must carry the SubagentStop hook tag."""
    from redaction_hooks.audit import read_entries
    from redaction_hooks.hooks import handle_stop

    transcript = tmp_path / "session.jsonl"
    _write_transcript(transcript, {"type": "assistant", "content": "leak: AKIAIOSFODNN7EXAMPLE"})
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {"hook_event_name": "SubagentStop", "transcript_path": str(transcript)}
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        capture_output(handle_stop, data, tmp_path)
    audits = read_entries(tmp_path)
    assert audits and audits[0]["hook"] == "SubagentStop"


def test_stop_handles_role_field(tmp_path: Path) -> None:
    """Transcript turns using `role` instead of `type` are also recognised."""
    from redaction_hooks.hooks import handle_stop

    transcript = tmp_path / "session.jsonl"
    _write_transcript(
        transcript,
        {"role": "assistant", "content": "key: AKIAIOSFODNN7EXAMPLE"},
    )
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {"hook_event_name": "Stop", "transcript_path": str(transcript)}
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        code, _ = capture_output(handle_stop, data, tmp_path)
    assert code == 0
    assert "aws-key" in stderr.getvalue()


def test_stop_handles_nested_message_role(tmp_path: Path) -> None:
    """Transcript turns where role is nested under `message.role` are recognised."""
    from redaction_hooks.hooks import handle_stop

    transcript = tmp_path / "session.jsonl"
    _write_transcript(
        transcript,
        {"message": {"role": "assistant", "content": "key: AKIAIOSFODNN7EXAMPLE"}},
    )
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {"hook_event_name": "Stop", "transcript_path": str(transcript)}
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        code, _ = capture_output(handle_stop, data, tmp_path)
    assert code == 0
    assert "aws-key" in stderr.getvalue()


def test_stop_no_assistant_message_is_no_op(tmp_path: Path) -> None:
    """Transcript with no assistant turns is a clean no-op."""
    from redaction_hooks.hooks import handle_stop

    transcript = tmp_path / "session.jsonl"
    _write_transcript(transcript, {"type": "user", "content": "AKIAIOSFODNN7EXAMPLE"})
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {"hook_event_name": "Stop", "transcript_path": str(transcript)}
    code, output = capture_output(handle_stop, data, tmp_path)
    assert code == 0
    assert output == {"continue": True}


def test_stop_unreadable_transcript_warns(tmp_path: Path) -> None:
    """A missing transcript_path emits stderr and returns continue:true."""
    from redaction_hooks.hooks import handle_stop

    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {
        "hook_event_name": "Stop",
        "transcript_path": str(tmp_path / "missing.jsonl"),
    }
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        code, _ = capture_output(handle_stop, data, tmp_path)
    assert code == 0
    assert "cannot read transcript" in stderr.getvalue()


def test_run_hook_dispatches_stop(tmp_path: Path) -> None:
    """run_hook routes Stop events."""
    transcript = tmp_path / "session.jsonl"
    _write_transcript(transcript, {"type": "assistant", "content": "ok"})
    (tmp_path / ".redaction_rules").write_text("rules:\n  - id: x\n    pattern: x")
    data = {"hook_event_name": "Stop", "transcript_path": str(transcript)}
    stdin = io.StringIO(json.dumps(data))
    stdout = io.StringIO()
    with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout):
        code = run_hook(tmp_path)
    assert code == 0


def test_post_compact_audits_secret_in_compacted_transcript(tmp_path: Path) -> None:
    """PostCompact warns + audits when the post-compaction transcript still leaks."""
    from redaction_hooks.audit import read_entries
    from redaction_hooks.hooks import handle_post_compact

    transcript = tmp_path / "session.jsonl"
    _write_transcript(
        transcript,
        {"type": "user", "content": "summary follows"},
        {"type": "assistant", "content": "Compaction summary: AKIAIOSFODNN7EXAMPLE was used"},
    )
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {
        "hook_event_name": "PostCompact",
        "transcript_path": str(transcript),
        "trigger": "auto",
    }
    stderr = io.StringIO()
    with patch.object(sys, "stderr", stderr):
        code, output = capture_output(handle_post_compact, data, tmp_path)
    assert code == 0  # PostCompact is warn-only
    assert output == {"continue": True}
    err = stderr.getvalue()
    assert "aws-key" in err
    assert "trigger=auto" in err
    audits = [e for e in read_entries(tmp_path) if e["hook"] == "PostCompact"]
    assert audits


def test_post_compact_clean_no_op(tmp_path: Path) -> None:
    """A clean compacted transcript writes no audit entry."""
    from redaction_hooks.audit import read_entries
    from redaction_hooks.hooks import handle_post_compact

    transcript = tmp_path / "session.jsonl"
    _write_transcript(transcript, {"type": "assistant", "content": "ok"})
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {
        "hook_event_name": "PostCompact",
        "transcript_path": str(transcript),
        "trigger": "manual",
    }
    code, _ = capture_output(handle_post_compact, data, tmp_path)
    assert code == 0
    assert read_entries(tmp_path) == []


def test_run_hook_dispatches_post_compact(tmp_path: Path) -> None:
    """run_hook routes PostCompact events."""
    transcript = tmp_path / "session.jsonl"
    _write_transcript(transcript, {"type": "assistant", "content": "ok"})
    (tmp_path / ".redaction_rules").write_text("rules:\n  - id: x\n    pattern: x")
    data = {
        "hook_event_name": "PostCompact",
        "transcript_path": str(transcript),
        "trigger": "auto",
    }
    stdin = io.StringIO(json.dumps(data))
    stdout = io.StringIO()
    with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout):
        code = run_hook(tmp_path)
    assert code == 0


def test_run_hook_dispatches_pre_compact(tmp_path: Path) -> None:
    """run_hook routes PreCompact events to handle_pre_compact."""
    transcript = tmp_path / "session.jsonl"
    _write_transcript(transcript, {"type": "user", "content": "clean"})
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {
        "hook_event_name": "PreCompact",
        "transcript_path": str(transcript),
        "trigger": "auto",
    }
    stdin = io.StringIO(json.dumps(data))
    stdout = io.StringIO()
    with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout):
        code = run_hook(tmp_path)
    assert code == 0


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
