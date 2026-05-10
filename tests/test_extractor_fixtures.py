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
from pathlib import Path
from typing import Any

import pytest

from redaction_hooks.hooks import (
    _get_tool_input_content,
    _get_tool_input_paths,
    _iter_output_fields,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "cc-payloads"


def _load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURE_DIR / name).read_text())
    return data


@pytest.mark.parametrize(
    ("fixture", "expected_paths", "expected_content_substr"),
    [
        ("PreToolUse-Bash.json", [], "echo hello"),
        ("PreToolUse-Read.json", ["<HOME>/<PROJECT>/README.md"], None),
    ],
)
def test_pre_tool_use_extractor_recognises_payload(
    fixture: str,
    expected_paths: list[str],
    expected_content_substr: str | None,
) -> None:
    """Phase 3: PreToolUse extractor returns non-empty content for known shapes.

    Bash payloads have `tool_input.command`; Read payloads have
    `tool_input.file_path`. If either name moves, this fails before the
    handler silently misses content in production.
    """
    data = _load(fixture)
    tool_name = data["tool_name"]
    tool_input = data["tool_input"]
    assert isinstance(tool_name, str) and isinstance(tool_input, dict)

    paths = _get_tool_input_paths(tool_name, tool_input)
    content = _get_tool_input_content(tool_name, tool_input)

    if expected_paths:
        assert paths == expected_paths, (
            f"path extractor returned {paths!r} for {fixture}; tool_input.file_path may have moved"
        )
    if expected_content_substr is not None:
        assert content is not None and expected_content_substr in content, (
            f"content extractor returned {content!r} for {fixture}; "
            "expected substring not found -- tool_input shape may have moved"
        )


@pytest.mark.parametrize(
    ("fixture", "must_match_field_substr"),
    [
        ("PostToolUse-Bash.json", ("stdout", "hello")),
        ("PostToolUse-Read.json", ("file.content", "First paragraph")),
        ("PostToolUse-REPL.json", ("result", "2")),
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

    fields = _iter_output_fields(tool_name, tool_response)
    assert fields, (
        f"_iter_output_fields returned [] for {fixture}; "
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
    failure-info field; `tool_input` is also scanned via `_get_tool_input_content`.
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
    content = _get_tool_input_content(tool_name, tool_input)
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
