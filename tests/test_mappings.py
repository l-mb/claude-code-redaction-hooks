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

"""Tests for persistent mappings."""

from pathlib import Path

from redaction_hooks.mappings import get_or_create_mapping, load_mappings, save_mappings


def test_load_empty(tmp_path: Path) -> None:
    """Test loading from non-existent file returns empty dict."""
    mappings = load_mappings(tmp_path)
    assert mappings == {}


def test_save_and_load(tmp_path: Path) -> None:
    """Test saving and loading mappings."""
    mappings = {"rule1": {"original": "replacement"}}
    save_mappings(mappings, tmp_path)
    loaded = load_mappings(tmp_path)
    assert loaded == mappings


def test_get_or_create_new(tmp_path: Path) -> None:
    """Test creating a new mapping."""
    result = get_or_create_mapping("rule", "original", lambda: "generated", tmp_path)
    assert result == "generated"

    # Verify it was persisted
    mappings = load_mappings(tmp_path)
    assert mappings["rule"]["original"] == "generated"


def test_get_or_create_existing(tmp_path: Path) -> None:
    """Test retrieving existing mapping doesn't call generator."""
    # Create initial mapping
    get_or_create_mapping("rule", "original", lambda: "first", tmp_path)

    # Second call should return cached value
    result = get_or_create_mapping("rule", "original", lambda: "second", tmp_path)
    assert result == "first"


def test_separate_rules(tmp_path: Path) -> None:
    """Test that different rules have separate mappings."""
    get_or_create_mapping("rule1", "text", lambda: "replacement1", tmp_path)
    get_or_create_mapping("rule2", "text", lambda: "replacement2", tmp_path)

    mappings = load_mappings(tmp_path)
    assert mappings["rule1"]["text"] == "replacement1"
    assert mappings["rule2"]["text"] == "replacement2"
