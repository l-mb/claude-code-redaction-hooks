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

"""Tests for redaction actions."""

from pathlib import Path

import pytest

from redaction_hooks.actions import apply_actions
from redaction_hooks.models import Match, Rule


@pytest.fixture
def isolated_dir(tmp_path: Path) -> Path:
    """Provide isolated directory for mappings."""
    return tmp_path


def test_block_action(isolated_dir: Path) -> None:
    """Test that block action returns block reasons."""
    rule = Rule(id="secret", pattern="xxx", action="block", description="Secret detected")
    match = Match(rule=rule, start=0, end=3, text="xxx")
    result = apply_actions("xxx data", [match], isolated_dir)
    assert len(result.block_reasons) == 1
    assert "[secret]" in result.block_reasons[0]
    assert result.redacted_text is None


def test_redact_literal(isolated_dir: Path) -> None:
    """Test redaction with literal replacement."""
    rule = Rule(id="pwd", pattern="password", action="redact", replacement="***")
    match = Match(rule=rule, start=4, end=12, text="password")
    result = apply_actions("the password is here", [match], isolated_dir)
    assert result.block_reasons == []
    assert result.redacted_text == "the *** is here"


def test_redact_default(isolated_dir: Path) -> None:
    """Test redaction with no replacement specified."""
    rule = Rule(id="pwd-default", pattern="password", action="redact")
    match = Match(rule=rule, start=0, end=8, text="password")
    result = apply_actions("password", [match], isolated_dir)
    assert result.redacted_text == "[REDACTED]"


def test_redact_ip(isolated_dir: Path) -> None:
    """Test IP replacement is deterministic."""
    rule = Rule(id="ip", pattern="xxx", action="redact", replacement="ip")
    match = Match(rule=rule, start=0, end=3, text="192.168.1.1")
    result = apply_actions("xxx", [match], isolated_dir)
    assert result.redacted_text is not None
    assert result.redacted_text.startswith("10.")
    # Same input produces same output (from mappings)
    result2 = apply_actions("xxx", [match], isolated_dir)
    assert result.redacted_text == result2.redacted_text


def test_redact_email(isolated_dir: Path) -> None:
    """Test email replacement."""
    rule = Rule(id="email", pattern="xxx", action="redact", replacement="email")
    match = Match(rule=rule, start=0, end=3, text="user@corp.com")
    result = apply_actions("xxx", [match], isolated_dir)
    assert result.redacted_text is not None
    assert "@example.com" in result.redacted_text
    assert result.redacted_text.startswith("redacted-")


def test_redact_hostname(isolated_dir: Path) -> None:
    """Test hostname replacement."""
    rule = Rule(id="host", pattern="xxx", action="redact", replacement="hostname")
    match = Match(rule=rule, start=0, end=3, text="server.internal")
    result = apply_actions("xxx", [match], isolated_dir)
    assert result.redacted_text is not None
    assert result.redacted_text.startswith("host-")
    assert result.redacted_text.endswith(".internal")


def test_multiple_redactions(isolated_dir: Path) -> None:
    """Test multiple redactions in same text."""
    rule = Rule(id="multi", pattern="xxx", action="redact", replacement="[EMAIL]")
    matches = [
        Match(rule=rule, start=0, end=5, text="alice"),
        Match(rule=rule, start=10, end=13, text="bob"),
    ]
    result = apply_actions("alice and bob here", matches, isolated_dir)
    assert result.redacted_text == "[EMAIL] and [EMAIL] here"


def test_no_matches(isolated_dir: Path) -> None:
    """Test with no matches returns original text."""
    result = apply_actions("clean text", [], isolated_dir)
    assert result.redacted_text == "clean text"
    assert result.block_reasons == []
    assert result.matches == []


def test_block_takes_priority(isolated_dir: Path) -> None:
    """Test that block action prevents redaction."""
    block_rule = Rule(id="blocker", pattern="xxx", action="block")
    redact_rule = Rule(id="redactor", pattern="yyy", action="redact", replacement="***")
    matches = [
        Match(rule=block_rule, start=0, end=3, text="xxx"),
        Match(rule=redact_rule, start=4, end=7, text="yyy"),
    ]
    result = apply_actions("xxx yyy", matches, isolated_dir)
    assert len(result.block_reasons) == 1
    assert result.redacted_text is None


def test_mapping_consistency(isolated_dir: Path) -> None:
    """Test that same input gets same replacement across calls."""
    rule = Rule(id="consistent", pattern="xxx", action="redact", replacement="email")
    match = Match(rule=rule, start=0, end=3, text="secret@corp.com")

    result1 = apply_actions("xxx", [match], isolated_dir)
    result2 = apply_actions("xxx", [match], isolated_dir)

    assert result1.redacted_text == result2.redacted_text
