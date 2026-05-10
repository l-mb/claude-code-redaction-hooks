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

"""Tests for CLI."""

import io
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from redaction_hooks.cli import main
from redaction_hooks.config import load_rules_file


@pytest.fixture
def project_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Set up a test project directory."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


def run_cli(*args: str, stdin_text: str = "") -> tuple[int, str, str]:
    """Run CLI with given args and capture output."""
    stdout = io.StringIO()
    stderr = io.StringIO()
    stdin = io.StringIO(stdin_text)
    with (
        patch.object(sys, "argv", ["redact", *args]),
        patch.object(sys, "stdout", stdout),
        patch.object(sys, "stderr", stderr),
        patch.object(sys, "stdin", stdin),
    ):
        try:
            code = main()
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 1
    return code, stdout.getvalue(), stderr.getvalue()


def test_secret_add_from_stdin(project_dir: Path) -> None:
    """Test adding secret from stdin."""
    code, out, err = run_cli("secret", "add", "--id", "test-secret", stdin_text="mysecret")
    assert code == 0
    assert "Added hashed rule" in err

    rules = load_rules_file(project_dir / ".redaction_rules")
    assert len(rules) == 1
    assert rules[0].id == "test-secret"
    assert rules[0].hashed is True


def test_secret_add_from_env(project_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test adding secret from environment variable."""
    monkeypatch.setenv("REDACT_SECRET", "envsecret")
    code, out, err = run_cli("secret", "add", "--id", "env-secret")
    assert code == 0

    rules = load_rules_file(project_dir / ".redaction_rules")
    assert len(rules) == 1
    assert rules[0].id == "env-secret"


def test_secret_add_empty_fails(project_dir: Path) -> None:
    """Test that empty secret fails."""
    code, out, err = run_cli("secret", "add", "--id", "empty", stdin_text="")
    assert code == 1
    assert "No secret provided" in err


def test_secret_add_with_action_redact_and_replacement(project_dir: Path) -> None:
    """`secret add --action redact --replacement '[X]'` persists both fields."""
    code, _, err = run_cli(
        "secret",
        "add",
        "--id",
        "redact-x",
        "--action",
        "redact",
        "--replacement",
        "[X]",
        stdin_text="abcdef",
    )
    assert code == 0, err
    rules = load_rules_file(project_dir / ".redaction_rules")
    assert len(rules) == 1
    assert rules[0].action == "redact"
    assert rules[0].replacement == "[X]"


def test_secret_add_with_target_llm(project_dir: Path) -> None:
    """`--target llm` is persisted on the saved rule."""
    code, _, err = run_cli(
        "secret",
        "add",
        "--id",
        "llm-only",
        "--target",
        "llm",
        stdin_text="abcdef",
    )
    assert code == 0, err
    rules = load_rules_file(project_dir / ".redaction_rules")
    assert rules[0].target == "llm"


def test_secret_add_with_custom_hash_extractor(project_dir: Path) -> None:
    """Custom --hash-extractor regex is persisted verbatim."""
    code, _, err = run_cli(
        "secret",
        "add",
        "--id",
        "long-only",
        "--hash-extractor",
        r"\b\w{8,}\b",
        stdin_text="longenough",
    )
    assert code == 0, err
    rules = load_rules_file(project_dir / ".redaction_rules")
    assert rules[0].hash_extractor == r"\b\w{8,}\b"


def test_secret_add_replacement_without_redact_errors(project_dir: Path) -> None:
    """`--replacement` is rejected with an explicit error when --action != redact."""
    code, _, err = run_cli(
        "secret",
        "add",
        "--id",
        "bad",
        "--replacement",
        "[X]",  # default --action is block
        stdin_text="abcdef",
    )
    assert code == 1
    assert "--replacement only applies to --action redact" in err
    # No rule should have been written.
    assert load_rules_file(project_dir / ".redaction_rules") == []


def test_secret_list(project_dir: Path) -> None:
    """Test listing hashed secrets."""
    # First add a secret
    run_cli("secret", "add", "--id", "listed", "--description", "Test", stdin_text="x")
    code, out, err = run_cli("secret", "list")
    assert code == 0
    assert "listed" in out
    assert "Test" in out


def test_secret_list_empty(project_dir: Path) -> None:
    """Test listing when no secrets exist."""
    code, out, err = run_cli("secret", "list")
    assert code == 0
    assert "No hashed rules" in err


def test_check_file(project_dir: Path) -> None:
    """Test checking a file for matches."""
    # Create rules
    (project_dir / ".redaction_rules").write_text("""
rules:
  - id: aws
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    # Create file to check
    test_file = project_dir / "test.txt"
    test_file.write_text("key = AKIAIOSFODNN7EXAMPLE")

    code, out, err = run_cli("check", str(test_file))
    assert code == 2
    assert "BLOCKED" in out


def test_check_clean_file(project_dir: Path) -> None:
    """Test checking a clean file."""
    (project_dir / ".redaction_rules").write_text("""
rules:
  - id: aws
    pattern: 'AKIA[0-9A-Z]{16}'
""")
    test_file = project_dir / "clean.txt"
    test_file.write_text("nothing secret here")

    code, out, err = run_cli("check", str(test_file))
    assert code == 0
    assert "No matches" in out


def test_check_missing_file(project_dir: Path) -> None:
    """Test checking non-existent file."""
    (project_dir / ".redaction_rules").write_text("rules:\n  - id: x\n    pattern: x")
    code, out, err = run_cli("check", "missing.txt")
    assert code == 1
    assert "not found" in err


def test_check_multiple_files(project_dir: Path) -> None:
    """Test checking multiple files."""
    (project_dir / ".redaction_rules").write_text("""
rules:
  - id: aws
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    (project_dir / "clean.txt").write_text("clean")
    (project_dir / "dirty.txt").write_text("AKIAIOSFODNN7EXAMPLE")

    code, out, err = run_cli("check", "clean.txt", "dirty.txt")
    assert code == 2
    assert "BLOCKED" in out


def test_check_with_rules_file(project_dir: Path) -> None:
    """Test check with custom --rules file."""
    rules_file = project_dir / "custom.yaml"
    rules_file.write_text("rules:\n  - id: test\n    pattern: SECRET\n    action: block")
    test_file = project_dir / "file.txt"
    test_file.write_text("contains SECRET here")

    code, out, err = run_cli("check", "--rules", str(rules_file), str(test_file))
    assert code == 2
    assert "BLOCKED" in out


def test_check_quiet_mode(project_dir: Path) -> None:
    """Test check with --quiet flag."""
    (project_dir / ".redaction_rules").write_text("rules:\n  - id: x\n    pattern: x")
    (project_dir / "clean.txt").write_text("clean")

    code, out, err = run_cli("check", "-q", "clean.txt")
    assert code == 0
    assert out == ""


def test_claude_setup(project_dir: Path) -> None:
    """Test claude-setup creates settings.json."""
    code, out, err = run_cli("claude-setup")
    assert code == 0

    settings_path = project_dir / ".claude" / "settings.json"
    assert settings_path.exists()

    with settings_path.open() as f:
        settings = json.load(f)
    assert "hooks" in settings
    assert "PreToolUse" in settings["hooks"]


def test_claude_setup_merges_existing(project_dir: Path) -> None:
    """Test claude-setup preserves unrelated top-level settings."""
    settings_dir = project_dir / ".claude"
    settings_dir.mkdir()
    settings_path = settings_dir / "settings.json"
    settings_path.write_text('{"existing": "value"}')

    code, out, err = run_cli("claude-setup")
    assert code == 0

    with settings_path.open() as f:
        settings = json.load(f)
    assert settings["existing"] == "value"
    assert "hooks" in settings


def test_claude_setup_preserves_other_tool_hook(project_dir: Path) -> None:
    """claude-setup must NOT overwrite another tool's hook on the same event."""
    settings_dir = project_dir / ".claude"
    settings_dir.mkdir()
    settings_path = settings_dir / "settings.json"
    other_tool = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Edit",
                    "hooks": [{"type": "command", "command": "ruff format"}],
                }
            ]
        }
    }
    settings_path.write_text(json.dumps(other_tool))

    code, out, err = run_cli("claude-setup")
    assert code == 0

    settings = json.loads(settings_path.read_text())
    pre = settings["hooks"]["PreToolUse"]
    commands = [h["command"] for entry in pre for h in entry["hooks"]]
    assert "ruff format" in commands
    assert "redact hook" in commands


def test_claude_setup_installs_without_matcher(project_dir: Path) -> None:
    """Installed redact-hook entries must omit `matcher` so they fire for every tool.

    Earlier versions used `matcher: "Write|Edit|Bash"` on PreToolUse and
    `Read|Bash|Grep|Glob|WebFetch` on PostToolUse, silently bypassing
    `tool: Read`, MultiEdit, WebSearch, Task/Agent, and MCP `mcp__*__*` tools.
    """
    code, out, err = run_cli("claude-setup")
    assert code == 0
    settings = json.loads((project_dir / ".claude" / "settings.json").read_text())
    for event in (
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",
        "InstructionsLoaded",
        "PostCompact",
        "Stop",
        "SubagentStop",
    ):
        entries = settings["hooks"][event]
        redact = [
            e for e in entries if any(h.get("command") == "redact hook" for h in e.get("hooks", []))
        ]
        assert redact, f"no redact entry on {event}"
        for entry in redact:
            assert "matcher" not in entry, f"{event} entry should omit matcher: {entry}"


def test_claude_setup_is_idempotent(project_dir: Path) -> None:
    """Running claude-setup twice must not duplicate the redact hook entry."""
    run_cli("claude-setup")
    run_cli("claude-setup")
    settings = json.loads((project_dir / ".claude" / "settings.json").read_text())
    pre = settings["hooks"]["PreToolUse"]
    redact_count = sum(1 for entry in pre for h in entry["hooks"] if h["command"] == "redact hook")
    assert redact_count == 1


def test_claude_setup_dry_run_does_not_write(project_dir: Path) -> None:
    """--dry-run prints the resulting settings.json but does not modify disk."""
    code, out, err = run_cli("claude-setup", "--dry-run")
    assert code == 0
    settings_path = project_dir / ".claude" / "settings.json"
    assert not settings_path.exists()
    settings = json.loads(out)
    assert "hooks" in settings


def test_claude_setup_uninstall_removes_only_redact_hook(project_dir: Path) -> None:
    """--uninstall removes only entries with `command == 'redact hook'`."""
    settings_dir = project_dir / ".claude"
    settings_dir.mkdir()
    settings_path = settings_dir / "settings.json"
    settings_path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Write|Edit|Bash",
                            "hooks": [
                                {"type": "command", "command": "redact hook"},
                                {"type": "command", "command": "another tool"},
                            ],
                        },
                        {
                            "matcher": "Edit",
                            "hooks": [{"type": "command", "command": "ruff format"}],
                        },
                    ]
                }
            }
        )
    )

    code, out, err = run_cli("claude-setup", "--uninstall")
    assert code == 0
    settings = json.loads(settings_path.read_text())
    pre = settings["hooks"]["PreToolUse"]
    commands = [h["command"] for entry in pre for h in entry["hooks"]]
    assert "redact hook" not in commands
    assert "another tool" in commands  # other commands in the same entry preserved
    assert "ruff format" in commands  # other entries preserved


def test_claude_setup_uninstall_when_nothing_present(project_dir: Path) -> None:
    """--uninstall on a settings.json without redact hooks is a no-op exit 0."""
    settings_dir = project_dir / ".claude"
    settings_dir.mkdir()
    settings_path = settings_dir / "settings.json"
    settings_path.write_text('{"hooks": {}}')

    code, out, err = run_cli("claude-setup", "--uninstall")
    assert code == 0
    assert "no redact-hook entries found" in err


def test_hook_subcommand_honours_claude_project_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`$CLAUDE_PROJECT_DIR` overrides cwd so rules/audit anchor to the project root."""
    real_project = tmp_path / "real-project"
    real_project.mkdir()
    (real_project / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    cwd = tmp_path / "elsewhere"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(real_project))

    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"content": "AKIAIOSFODNN7EXAMPLE", "file_path": "x.py"},
    }
    code, out, err = run_cli("hook", stdin_text=json.dumps(data))
    assert code == 2  # rule fired despite cwd containing no rules
    audit = real_project / ".claude" / "redaction_audit.log"
    assert audit.exists(), "audit log should land in CLAUDE_PROJECT_DIR"


def test_hook_subcommand_warns_on_invalid_claude_project_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An invalid `$CLAUDE_PROJECT_DIR` is reported and we fall back to cwd."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path / "does-not-exist"))
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"content": "AKIAIOSFODNN7EXAMPLE", "file_path": "x.py"},
    }
    code, out, err = run_cli("hook", stdin_text=json.dumps(data))
    assert code == 2  # cwd's rules are loaded after the fallback
    assert "is not a directory" in err
    audit = tmp_path / ".claude" / "redaction_audit.log"
    assert audit.exists(), "audit log should land in cwd after invalid env fallback"


def test_hook_subcommand_defaults_to_cwd_when_env_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With `CLAUDE_PROJECT_DIR` unset, the hook anchors to cwd (not global)."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    (tmp_path / ".redaction_rules").write_text("""
rules:
  - id: aws-key
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
""")
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"content": "AKIAIOSFODNN7EXAMPLE", "file_path": "x.py"},
    }
    code, _, _ = run_cli("hook", stdin_text=json.dumps(data))
    assert code == 2
    audit = tmp_path / ".claude" / "redaction_audit.log"
    assert audit.exists(), "audit log must land in cwd, not the user-global path"


def test_hook_subcommand(project_dir: Path) -> None:
    """Test hook subcommand processes stdin."""
    data = {"hook_event_name": "UnknownEvent"}
    code, out, err = run_cli("hook", stdin_text=json.dumps(data))
    assert code == 0
    output = json.loads(out)
    assert output["continue"] is True


def test_audit_tail(project_dir: Path) -> None:
    """Test `redact audit tail` prints recent entries."""
    from redaction_hooks.audit import log_event

    for i in range(5):
        log_event("PreToolUse", "block", [f"rule-{i}"], tool="Bash", project_dir=project_dir)
    code, out, err = run_cli("audit", "tail", "-n", "3")
    assert code == 0
    lines = [json.loads(line) for line in out.strip().splitlines()]
    assert [e["rule_ids"][0] for e in lines] == ["rule-2", "rule-3", "rule-4"]


def test_audit_tail_empty(project_dir: Path) -> None:
    """`audit tail` on a fresh project is silent and exits 0."""
    code, out, err = run_cli("audit", "tail")
    assert code == 0
    assert out == ""


def test_audit_since(project_dir: Path) -> None:
    """`audit since` filters by age."""
    from redaction_hooks.audit import log_event

    log_event("PreToolUse", "block", ["recent"], project_dir=project_dir)
    code, out, err = run_cli("audit", "since", "1h")
    assert code == 0
    assert "recent" in out


def test_audit_since_rejects_bad_duration(project_dir: Path) -> None:
    """An invalid duration string is reported and exits 1."""
    code, out, err = run_cli("audit", "since", "garbage")
    assert code == 1
    assert "invalid duration" in err
