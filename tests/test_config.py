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

"""Tests for configuration loading."""

from pathlib import Path

import pytest

from redaction_hooks.config import (
    add_hashed_rule,
    load_rules,
    load_rules_file,
    save_rules_file,
)
from redaction_hooks.matcher import hash_text
from redaction_hooks.models import Rule


@pytest.fixture
def tmp_rules_file(tmp_path: Path) -> Path:
    """Create a temporary rules file."""
    return tmp_path / ".redaction_rules"


def test_load_empty_file(tmp_rules_file: Path) -> None:
    """Test loading from non-existent file returns empty list."""
    rules = load_rules_file(tmp_rules_file)
    assert rules == []


def test_load_rules_file(tmp_rules_file: Path) -> None:
    """Test loading rules from YAML file."""
    tmp_rules_file.write_text("""
rules:
  - id: test-rule
    pattern: "secret.*"
    action: block
    description: Test rule
""")
    rules = load_rules_file(tmp_rules_file)
    assert len(rules) == 1
    assert rules[0].id == "test-rule"
    assert rules[0].pattern == "secret.*"
    assert rules[0].action == "block"


def test_save_rules_file(tmp_rules_file: Path) -> None:
    """Test saving rules to YAML file."""
    rules = [
        Rule(id="rule1", pattern="abc", description="First rule"),
        Rule(id="rule2", pattern="def", action="redact", replacement="***"),
    ]
    save_rules_file(tmp_rules_file, rules)

    loaded = load_rules_file(tmp_rules_file)
    assert len(loaded) == 2
    assert loaded[0].id == "rule1"
    assert loaded[1].id == "rule2"
    assert loaded[1].action == "redact"


def test_load_rules_merges_global_and_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test that project rules override global rules."""
    global_dir = tmp_path / "global"
    global_dir.mkdir()
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    # Patch GLOBAL_RULES_FILE
    monkeypatch.setattr("redaction_hooks.config.GLOBAL_RULES_FILE", global_dir / ".redaction_rules")

    # Create global rules
    (global_dir / ".redaction_rules").write_text("""
rules:
  - id: shared-rule
    pattern: global-pattern
  - id: global-only
    pattern: global-only-pattern
""")

    # Create project rules
    (project_dir / ".redaction_rules").write_text("""
rules:
  - id: shared-rule
    pattern: project-pattern
  - id: project-only
    pattern: project-only-pattern
""")

    rules = load_rules(project_dir)
    rules_by_id = {r.id: r for r in rules}

    assert len(rules) == 3
    assert rules_by_id["shared-rule"].pattern == "project-pattern"  # Project overrides
    assert rules_by_id["global-only"].pattern == "global-only-pattern"
    assert rules_by_id["project-only"].pattern == "project-only-pattern"


def test_add_hashed_rule(tmp_path: Path) -> None:
    """Test adding a hashed rule."""
    rule = add_hashed_rule(
        secret="MySecret",
        rule_id="secret-id",
        description="A hashed secret",
        project_dir=tmp_path,
    )

    assert rule.hashed is True
    assert rule.pattern == hash_text("MySecret")

    # Verify it was saved
    loaded = load_rules_file(tmp_path / ".redaction_rules")
    assert len(loaded) == 1
    assert loaded[0].id == "secret-id"
    assert loaded[0].hashed is True


def test_add_hashed_rule_replaces_existing(tmp_path: Path) -> None:
    """Test that adding a rule with same id replaces the old one."""
    add_hashed_rule(secret="First", rule_id="test", project_dir=tmp_path)
    add_hashed_rule(secret="Second", rule_id="test", project_dir=tmp_path)

    loaded = load_rules_file(tmp_path / ".redaction_rules")
    assert len(loaded) == 1
    assert loaded[0].pattern == hash_text("Second")


def test_validate_valid_rules(tmp_rules_file: Path) -> None:
    """Test validation passes for valid rules."""
    from redaction_hooks.config import validate_rules_file

    tmp_rules_file.write_text("""
rules:
  - id: test-rule
    pattern: "secret.*"
    action: block
""")
    errors = validate_rules_file(tmp_rules_file)
    assert errors == []


def test_validate_missing_file(tmp_path: Path) -> None:
    """Test validation returns empty for non-existent file."""
    from redaction_hooks.config import validate_rules_file

    errors = validate_rules_file(tmp_path / "nonexistent")
    assert errors == []


def test_validate_invalid_yaml(tmp_rules_file: Path) -> None:
    """Test validation catches YAML syntax errors."""
    from redaction_hooks.config import validate_rules_file

    tmp_rules_file.write_text("rules: [invalid yaml")
    errors = validate_rules_file(tmp_rules_file)
    assert len(errors) == 1
    assert "YAML syntax error" in errors[0]


def test_validate_missing_id(tmp_rules_file: Path) -> None:
    """Test validation catches missing id field."""
    from redaction_hooks.config import validate_rules_file

    tmp_rules_file.write_text("""
rules:
  - pattern: "test"
""")
    errors = validate_rules_file(tmp_rules_file)
    assert any("missing required field 'id'" in e for e in errors)


def test_validate_missing_pattern(tmp_rules_file: Path) -> None:
    """Test validation catches missing pattern and path_pattern fields."""
    from redaction_hooks.config import validate_rules_file

    tmp_rules_file.write_text("""
rules:
  - id: test
""")
    errors = validate_rules_file(tmp_rules_file)
    assert any("must have 'pattern' or 'path_pattern'" in e for e in errors)


def test_validate_invalid_regex(tmp_rules_file: Path) -> None:
    """Test validation catches invalid regex patterns."""
    from redaction_hooks.config import validate_rules_file

    tmp_rules_file.write_text("""
rules:
  - id: test
    pattern: "[invalid"
""")
    errors = validate_rules_file(tmp_rules_file)
    assert any("invalid regex pattern" in e for e in errors)


def test_validate_invalid_action(tmp_rules_file: Path) -> None:
    """Test validation catches invalid action values."""
    from redaction_hooks.config import validate_rules_file

    tmp_rules_file.write_text("""
rules:
  - id: test
    pattern: "test"
    action: invalid
""")
    errors = validate_rules_file(tmp_rules_file)
    assert any("invalid action" in e for e in errors)


def test_validate_invalid_target(tmp_rules_file: Path) -> None:
    """Test validation catches invalid target values."""
    from redaction_hooks.config import validate_rules_file

    tmp_rules_file.write_text("""
rules:
  - id: test
    pattern: "test"
    target: invalid
""")
    errors = validate_rules_file(tmp_rules_file)
    assert any("invalid target" in e for e in errors)


def test_validate_duplicate_ids(tmp_rules_file: Path) -> None:
    """Test validation catches duplicate rule ids."""
    from redaction_hooks.config import validate_rules_file

    tmp_rules_file.write_text("""
rules:
  - id: dupe
    pattern: "test1"
  - id: dupe
    pattern: "test2"
""")
    errors = validate_rules_file(tmp_rules_file)
    assert any("duplicate id" in e for e in errors)
