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

import pytest

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


def _concurrency_worker(args: tuple[str, int]) -> str:
    """Module-level worker for ProcessPoolExecutor.map (must be picklable)."""
    project_dir, idx = args
    return get_or_create_mapping("rule", "secret", lambda: f"replacement-{idx}", Path(project_dir))


def test_concurrent_workers_agree_on_replacement(tmp_path: Path) -> None:
    """N concurrent workers must all see the same replacement value.

    Without locking, the load-modify-write race produces divergent replacements
    and silently corrupts deterministic redaction across sessions.
    """
    import multiprocessing
    from concurrent.futures import ProcessPoolExecutor

    n = 16
    ctx = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=n, mp_context=ctx) as ex:
        results = list(ex.map(_concurrency_worker, [(str(tmp_path), i) for i in range(n)]))

    assert len(set(results)) == 1, f"got divergent replacements: {set(results)}"
    persisted = load_mappings(tmp_path)
    assert persisted["rule"]["secret"] == results[0]


def test_load_quarantines_corrupt_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """A corrupt mappings file is renamed aside, not silently erased."""
    path = tmp_path / ".claude" / "redaction_mappings.json"
    path.parent.mkdir(parents=True)
    path.write_text("{ this is not valid json")

    mappings = load_mappings(tmp_path)
    assert mappings == {}
    assert not path.exists()
    quarantines = list(path.parent.glob(f"{path.name}.corrupt-*"))
    assert len(quarantines) == 1
    assert "not valid json" in quarantines[0].read_text()
    assert "corrupt mappings file" in capsys.readouterr().err


def test_save_is_atomic_no_partial_file_on_error(tmp_path: Path) -> None:
    """If json.dump raises, no partial mappings file is left behind."""
    from contextlib import suppress
    from unittest.mock import patch

    path = tmp_path / ".claude" / "redaction_mappings.json"
    path.parent.mkdir(parents=True)
    path.write_text('{"mappings": {"rule": {"k": "v"}}}')
    original = path.read_text()

    with patch("json.dump", side_effect=RuntimeError("disk full")), suppress(RuntimeError):
        save_mappings({"rule": {"new": "value"}}, tmp_path)

    # Original file untouched; no leftover .tmp files
    assert path.read_text() == original
    leftovers = [p for p in path.parent.iterdir() if p.name.endswith(".tmp")]
    assert leftovers == []
