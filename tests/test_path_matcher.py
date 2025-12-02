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

"""Tests for path-based matching."""

from pathlib import Path

from redaction_hooks.models import Rule
from redaction_hooks.path_matcher import PathMatcher


def test_match_absolute_path() -> None:
    """Test matching absolute path patterns."""
    rule = Rule(id="etc-passwd", path_pattern="/etc/passwd")
    matcher = PathMatcher([rule])
    matches = matcher.scan(["/etc/passwd"], "tool")
    assert len(matches) == 1
    assert matches[0].rule.id == "etc-passwd"


def test_match_glob_pattern() -> None:
    """Test matching glob patterns like *.env."""
    rule = Rule(id="env-files", path_pattern="*.env")
    matcher = PathMatcher([rule])
    assert len(matcher.scan(["/home/user/.env"], "tool")) == 1
    assert len(matcher.scan(["/project/.env.local"], "tool")) == 0  # doesn't end with .env
    assert len(matcher.scan(["config.env"], "tool")) == 1


def test_match_double_star_glob() -> None:
    """Test matching **/ patterns for any directory depth."""
    rule = Rule(id="secrets-dir", path_pattern="**/secrets/*")
    matcher = PathMatcher([rule])
    assert len(matcher.scan(["/app/secrets/key.pem"], "tool")) == 1
    assert len(matcher.scan(["/deep/nested/secrets/token"], "tool")) == 1
    assert len(matcher.scan(["/app/config/key.pem"], "tool")) == 0


def test_match_relative_to_project(tmp_path: Path) -> None:
    """Test matching paths relative to project directory."""
    rule = Rule(id="local-env", path_pattern=".env")
    matcher = PathMatcher([rule], project_dir=tmp_path)
    # Path within project
    assert len(matcher.scan([str(tmp_path / ".env")], "tool")) == 1
    # Relative path resolved against project
    matches = matcher.scan([".env"], "tool")
    assert len(matches) == 1


def test_match_filename_only() -> None:
    """Test matching just the filename component."""
    rule = Rule(id="credentials", path_pattern="credentials.json")
    matcher = PathMatcher([rule])
    assert len(matcher.scan(["/any/path/to/credentials.json"], "tool")) == 1
    assert len(matcher.scan(["/other/credentials.json"], "tool")) == 1


def test_target_filtering() -> None:
    """Test that path rules filter by target."""
    rule = Rule(id="tool-only", path_pattern="*.secret", target="tool")
    matcher = PathMatcher([rule])
    assert len(matcher.scan(["data.secret"], "tool")) == 1
    assert len(matcher.scan(["data.secret"], "llm")) == 0


def test_tool_filtering() -> None:
    """Test that path rules filter by tool name."""
    rule = Rule(id="read-only", path_pattern="*.env", tool="Read")
    matcher = PathMatcher([rule])
    assert len(matcher.scan(["config.env"], "tool", "Read")) == 1
    assert len(matcher.scan(["config.env"], "tool", "Write")) == 0


def test_multiple_paths() -> None:
    """Test scanning multiple paths at once."""
    rule = Rule(id="env-files", path_pattern="*.env")
    matcher = PathMatcher([rule])
    matches = matcher.scan(["/app/.env", "/app/config.yaml", "/app/secrets.env"], "tool")
    assert len(matches) == 2


def test_no_path_rules() -> None:
    """Test that matcher ignores rules without path_pattern."""
    content_rule = Rule(id="content-only", pattern="secret")
    matcher = PathMatcher([content_rule])
    assert len(matcher.rules) == 0
    assert len(matcher.scan(["/any/path"], "tool")) == 0


def test_home_expansion() -> None:
    """Test that ~ is expanded to home directory."""
    rule = Rule(id="ssh-keys", path_pattern="~/.ssh/*")
    matcher = PathMatcher([rule])
    home = Path.home()
    # Match when using full path
    assert len(matcher.scan([str(home / ".ssh/id_rsa")], "tool")) == 1


def test_combined_rule_only_path_in_path_matcher() -> None:
    """Test that combined rules (path+pattern) are included in PathMatcher."""
    combined_rule = Rule(id="combined", path_pattern="*.env", pattern="SECRET=")
    matcher = PathMatcher([combined_rule])
    assert len(matcher.rules) == 1
    # PathMatcher only checks path, not content
    assert len(matcher.scan(["config.env"], "tool")) == 1


def test_match_with_action() -> None:
    """Test that different actions are preserved in matches."""
    block_rule = Rule(id="block-env", path_pattern="*.env", action="block")
    warn_rule = Rule(id="warn-tmp", path_pattern="/tmp/*", action="warn")
    matcher = PathMatcher([block_rule, warn_rule])

    env_matches = matcher.scan(["config.env"], "tool")
    assert len(env_matches) == 1
    assert env_matches[0].rule.action == "block"

    tmp_matches = matcher.scan(["/tmp/data"], "tool")
    assert len(tmp_matches) == 1
    assert tmp_matches[0].rule.action == "warn"
