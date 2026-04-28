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

"""Tests for the structured audit log."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from redaction_hooks.audit import log_event, parse_duration, read_entries


def test_log_event_appends_jsonl(tmp_path: Path) -> None:
    """log_event appends one JSON line per call with the expected fields."""
    log_event("PreToolUse", "block", ["aws-key"], tool="Bash", project_dir=tmp_path)
    log_event("PostToolUse", "redact", ["email", "ssn"], tool="Read", project_dir=tmp_path)
    entries = read_entries(tmp_path)
    assert len(entries) == 2
    assert entries[0]["hook"] == "PreToolUse"
    assert entries[0]["action"] == "block"
    assert entries[0]["rule_ids"] == ["aws-key"]
    assert entries[0]["tool"] == "Bash"
    assert "ts" in entries[0]
    datetime.fromisoformat(entries[0]["ts"])  # parses as ISO 8601
    assert entries[1]["rule_ids"] == ["email", "ssn"]


def test_log_event_skips_when_no_rule_ids(tmp_path: Path) -> None:
    """Empty rule_ids list is a no-op (no entry written)."""
    log_event("PreToolUse", "warn", [], tool="Bash", project_dir=tmp_path)
    assert read_entries(tmp_path) == []


def test_log_event_never_includes_secret_text(tmp_path: Path) -> None:
    """The audit log API has no field for matched text -- only rule IDs.

    Regression guard: if someone adds a 'matched_text' field, this fails.
    """
    log_event("PreToolUse", "block", ["secret-rule"], tool="Bash", project_dir=tmp_path)
    raw = (tmp_path / ".claude" / "redaction_audit.log").read_text()
    obj = json.loads(raw.strip())
    forbidden = {"text", "match", "matched_text", "secret", "value", "content"}
    assert not (forbidden & obj.keys()), f"forbidden fields in audit entry: {obj.keys()}"


def _audit_worker(args: tuple[str, int]) -> None:
    project_dir, idx = args
    log_event(
        "PreToolUse",
        "block",
        [f"rule-{idx}"],
        tool="Bash",
        project_dir=Path(project_dir),
    )


def test_concurrent_writes_no_lost_entries(tmp_path: Path) -> None:
    """N concurrent writers produce N entries (atomic O_APPEND)."""
    import multiprocessing
    from concurrent.futures import ProcessPoolExecutor

    n = 32
    ctx = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=n, mp_context=ctx) as ex:
        list(ex.map(_audit_worker, [(str(tmp_path), i) for i in range(n)]))
    entries = read_entries(tmp_path)
    assert len(entries) == n
    assert {entry["rule_ids"][0] for entry in entries} == {f"rule-{i}" for i in range(n)}


def test_read_entries_skips_corrupt_lines(tmp_path: Path) -> None:
    """A garbled line in the middle of the file is silently skipped."""
    path = tmp_path / ".claude" / "redaction_audit.log"
    path.parent.mkdir(parents=True)
    path.write_text(
        '{"hook":"a","action":"b","rule_ids":["r1"]}\n'
        "this is not json\n"
        '{"hook":"c","action":"d","rule_ids":["r2"]}\n'
    )
    entries = read_entries(tmp_path)
    assert [e["rule_ids"] for e in entries] == [["r1"], ["r2"]]


def test_parse_duration_units() -> None:
    assert parse_duration("30s") == 30
    assert parse_duration("5m") == 300
    assert parse_duration("2h") == 7200
    assert parse_duration("1d") == 86400
    assert parse_duration("1w") == 604800


@pytest.mark.parametrize("bad", ["", "1", "1x", "abc", "-1h", "1.5h"])
def test_parse_duration_rejects_garbage(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_duration(bad)


def test_read_entries_empty_when_no_log(tmp_path: Path) -> None:
    assert read_entries(tmp_path) == []


def test_log_event_handles_old_iso_timestamps(tmp_path: Path) -> None:
    """The since-filter logic must accept ISO timestamps written by us."""
    log_event("PreToolUse", "block", ["r1"], project_dir=tmp_path)
    entries = read_entries(tmp_path)
    ts = datetime.fromisoformat(entries[0]["ts"])
    assert ts <= datetime.now(UTC)
    assert ts > datetime.now(UTC) - timedelta(seconds=10)
