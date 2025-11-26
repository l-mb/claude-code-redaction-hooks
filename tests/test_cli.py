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
    """Test claude-setup merges with existing settings."""
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


def test_hook_subcommand(project_dir: Path) -> None:
    """Test hook subcommand processes stdin."""
    data = {"hook_event_name": "UnknownEvent"}
    code, out, err = run_cli("hook", stdin_text=json.dumps(data))
    assert code == 0
    output = json.loads(out)
    assert output["continue"] is True
