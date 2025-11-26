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

"""Tests for pattern matching engine."""

from redaction_hooks.matcher import PatternMatcher, hash_text
from redaction_hooks.models import Rule


def test_hash_text() -> None:
    """Test SHA-256 hashing."""
    h = hash_text("secret")
    assert len(h) == 64
    assert h == "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"


def test_match_regex() -> None:
    """Test regex pattern matching."""
    rule = Rule(id="aws-key", pattern=r"AKIA[0-9A-Z]{16}")
    matcher = PatternMatcher([rule])
    matches = matcher.scan("key: AKIAIOSFODNN7EXAMPLE", "llm")
    assert len(matches) == 1
    assert matches[0].text == "AKIAIOSFODNN7EXAMPLE"
    assert matches[0].start == 5
    assert matches[0].end == 25


def test_match_fixed_string() -> None:
    """Test fixed string matching."""
    rule = Rule(id="literal", pattern="password123", is_regex=False)
    matcher = PatternMatcher([rule])
    matches = matcher.scan("the password123 is here", "tool")
    assert len(matches) == 1
    assert matches[0].text == "password123"


def test_match_hashed() -> None:
    """Test hashed pattern matching."""
    secret_hash = hash_text("ProjectAlpha")
    rule = Rule(
        id="secret-project",
        pattern=secret_hash,
        hashed=True,
        hash_extractor=r"\b[A-Z][a-zA-Z]+\b",
    )
    matcher = PatternMatcher([rule])
    matches = matcher.scan("Working on ProjectAlpha today", "llm")
    assert len(matches) == 1
    assert matches[0].text == "ProjectAlpha"
    assert matches[0].segment_hash == secret_hash


def test_target_filtering() -> None:
    """Test that rules filter by target."""
    llm_rule = Rule(id="llm-only", pattern="secret", target="llm")
    tool_rule = Rule(id="tool-only", pattern="secret", target="tool")
    matcher = PatternMatcher([llm_rule, tool_rule])

    llm_matches = matcher.scan("secret data", "llm")
    assert len(llm_matches) == 1
    assert llm_matches[0].rule.id == "llm-only"

    tool_matches = matcher.scan("secret data", "tool")
    assert len(tool_matches) == 1
    assert tool_matches[0].rule.id == "tool-only"


def test_both_target() -> None:
    """Test that 'both' target matches all contexts."""
    rule = Rule(id="both", pattern="secret", target="both")
    matcher = PatternMatcher([rule])
    assert len(matcher.scan("secret", "llm")) == 1
    assert len(matcher.scan("secret", "tool")) == 1


def test_multiple_matches() -> None:
    """Test multiple matches in same text."""
    rule = Rule(id="email", pattern=r"[a-z]+@example\.com")
    matcher = PatternMatcher([rule])
    matches = matcher.scan("contact alice@example.com or bob@example.com", "llm")
    assert len(matches) == 2
    assert matches[0].text == "alice@example.com"
    assert matches[1].text == "bob@example.com"


def test_no_matches() -> None:
    """Test when no patterns match."""
    rule = Rule(id="aws-key", pattern=r"AKIA[0-9A-Z]{16}")
    matcher = PatternMatcher([rule])
    matches = matcher.scan("no secrets here", "llm")
    assert len(matches) == 0
