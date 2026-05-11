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

"""Regression tests for the per-tool extractors against captured CC payloads.

The fixtures in tests/fixtures/cc-payloads/ are anonymised real payloads
captured via the `tee | redact hook` instrumentation against CC v2.1.x.
Each test asserts that the named-field extractor (NOT the recursive backstop)
returns at least one non-empty piece of content for that fixture. If CC
ships a shape change, the named-field path stops returning content, the test
fails, and the operator updates both the fixture (with `redact verify-cc-schema
--update-golden` once Phase 5 ships, or by hand) and the extractor in
hooks.py to recognise the new shape.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from redaction_hooks.extractors import (
    get_tool_input_content,
    get_tool_input_paths,
    iter_output_fields,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "cc-payloads"


def _load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURE_DIR / name).read_text())
    return data


@pytest.mark.parametrize(
    ("fixture", "expected_path_regex", "expected_content_substr"),
    [
        # `expected_path_regex` is matched against `paths[0]` after asserting
        # exactly one path was extracted. None = path-extractor not asserted
        # (the tool has no path input). Substrings reference the harness's
        # `redact-verify` canary or stable seeded filenames -- the harness's
        # `update_golden` overwrites fixtures with whichever capture happened
        # most recently, so basenames vary between runs (note.txt vs multi.txt
        # for Read, etc.); the regex tolerates this while still proving the
        # extractor returned a path of the expected shape.
        ("PreToolUse-Bash.json", None, "<PROJECT>"),
        ("PreToolUse-Read.json", r"^<PROJECT>/[\w.-]+$", None),
        # Grep can receive a relative or absolute path depending on the model -- accept both.
        ("PreToolUse-Grep.json", r"^(<PROJECT>/)?README\.md$", "rules"),
        ("PreToolUse-Agent.json", None, "list cwd files"),
        ("PreToolUse-Edit.json", r"^<PROJECT>/[\w.-]+$", "redact-verify"),
        ("PreToolUse-Write.json", r"^<PROJECT>/[\w.-]+$", "redact-verify"),
        ("PreToolUse-Glob.json", None, "*.md"),
        ("PreToolUse-ToolSearch.json", None, "select:"),
    ],
)
def test_pre_tool_use_extractor_recognises_payload(
    fixture: str,
    expected_path_regex: str | None,
    expected_content_substr: str | None,
) -> None:
    """PreToolUse extractor returns non-empty content for every known shape.

    Bash → command, Read → file_path, Grep → pattern + path,
    Agent → description + prompt, Edit/Write → file_path + content/new_string,
    Glob → pattern, ToolSearch → query. If any of these names moves, this
    fails before the handler silently misses content in production.
    """
    data = _load(fixture)
    tool_name = data["tool_name"]
    tool_input = data["tool_input"]
    assert isinstance(tool_name, str) and isinstance(tool_input, dict)

    paths = get_tool_input_paths(tool_name, tool_input)
    content = get_tool_input_content(tool_name, tool_input)

    if expected_path_regex is not None:
        assert len(paths) == 1, (
            f"expected exactly one path for {fixture}, got {paths!r}; "
            "tool_input path key may have moved or been duplicated"
        )
        assert re.match(expected_path_regex, paths[0]), (
            f"path {paths[0]!r} does not match {expected_path_regex!r} for {fixture}; "
            "extracted path shape may have changed"
        )
    if expected_content_substr is not None:
        assert content is not None and expected_content_substr in content, (
            f"content extractor returned {content!r} for {fixture}; "
            "expected substring not found -- tool_input shape may have moved"
        )


@pytest.mark.parametrize(
    ("fixture", "must_match_field_substr"),
    [
        # Bash stdout content is whatever the most-recent harness Bash capture
        # produced -- presently the subagent's `ls <PROJECT>` listing -- so we
        # assert on a substring guaranteed to appear in any directory listing of
        # the seeded harness project.
        ("PostToolUse-Bash.json", ("stdout", "README.md")),
        ("PostToolUse-Read.json", ("file.content", "redact-verify")),
        ("PostToolUse-REPL.json", ("result", "2")),
        ("PostToolUse-Grep.json", ("filenames[0]", "README.md")),
        ("PostToolUse-Glob.json", ("filenames[0]", "README.md")),
        ("PostToolUse-Write.json", ("content", "redact-verify")),
        # Edit response has no `content` key; `originalFile` carries the pre-image.
        ("PostToolUse-Edit.json", ("originalFile", "redact-verify")),
        # ToolSearch response: `query` echoes the input query string.
        ("PostToolUse-ToolSearch.json", ("query", "select:")),
        ("PostToolUse-Agent.json", ("content[0].text", "DONE")),
    ],
)
def test_post_tool_use_extractor_recognises_payload(
    fixture: str,
    must_match_field_substr: tuple[str, str],
) -> None:
    """Phase 3: PostToolUse named-field extractor catches each tool's content.

    Each fixture must produce at least one (field_path, content) pair via the
    named-field extractor (no recursive fallback). Asserting on the exact
    field_path catches renames; asserting on a substring catches deeper shape
    changes.
    """
    data = _load(fixture)
    tool_name = data["tool_name"]
    tool_response = data["tool_response"]
    assert isinstance(tool_name, str)

    fields = iter_output_fields(tool_name, tool_response)
    assert fields, (
        f"iter_output_fields returned [] for {fixture}; "
        "this means production hits the recursive fallback (block-only) and "
        "loses redact capability -- update the per-tool field list in hooks.py"
    )

    expected_field, expected_substr = must_match_field_substr
    matching = [(path, content) for path, content in fields if path == expected_field]
    assert matching, (
        f"expected field_path {expected_field!r} in extracted fields, "
        f"got {[p for p, _ in fields]!r} -- the field may have been renamed"
    )
    assert expected_substr in matching[0][1], (
        f"expected substring {expected_substr!r} in extracted content "
        f"{matching[0][1]!r}; shape may have changed"
    )


def test_post_tool_use_failure_extractor_recognises_payload() -> None:
    """Phase 3: PostToolUseFailure -- the `error` key is the canonical
    failure-info field; `tool_input` is also scanned via `get_tool_input_content`.
    """
    data = _load("PostToolUseFailure-Bash.json")
    assert "error" in data, (
        "PostToolUseFailure fixture must carry `error` key; if it doesn't, "
        "the upstream payload has drifted"
    )
    assert isinstance(data["error"], str) and data["error"]
    tool_name = data["tool_name"]
    tool_input = data["tool_input"]
    assert isinstance(tool_name, str) and isinstance(tool_input, dict)
    content = get_tool_input_content(tool_name, tool_input)
    assert content and "ls" in content


def test_every_fixture_carries_required_top_level_keys() -> None:
    """Phase 3: hook_event_name must be present on every payload (otherwise
    run_hook can't dispatch). Cheap drift canary."""
    for fixture_path in sorted(FIXTURE_DIR.glob("*.json")):
        data = json.loads(fixture_path.read_text())
        assert "hook_event_name" in data, (
            f"{fixture_path.name} missing hook_event_name -- corrupt fixture"
        )
        assert "session_id" in data, (
            f"{fixture_path.name} missing session_id -- this is a common-input "
            "field present on every CC hook event; recapture and update"
        )


def test_post_tool_batch_fixture_walks_tool_calls() -> None:
    """If a PostToolBatch fixture is captured, every tool_calls[] entry must
    have the keys our handler walks (tool_name + tool_response). Skip when
    the fixture isn't in the corpus yet (Phase 7 may not have captured one)."""
    fixture_path = FIXTURE_DIR / "PostToolBatch.json"
    if not fixture_path.exists():
        pytest.skip("PostToolBatch fixture not yet captured -- see Phase 7 / verify-cc-schema")
    data = json.loads(fixture_path.read_text())
    tool_calls = data.get("tool_calls")
    assert isinstance(tool_calls, list) and tool_calls, (
        "PostToolBatch fixture must carry a non-empty tool_calls array"
    )
    for entry in tool_calls:
        assert isinstance(entry, dict)
        assert "tool_name" in entry, "each tool_calls entry must name its tool"
        assert "tool_response" in entry, "each tool_calls entry must carry tool_response"
