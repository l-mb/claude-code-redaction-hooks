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

"""Unit tests for the deterministic parts of the verify-cc-schema harness.

The `claude -p` invocation itself is not exercised here -- it requires a real
CC binary + API and would burn credits in pytest. We test the building blocks:
classification, anonymisation, golden updates, and report formatting.
"""

from __future__ import annotations

import json
from pathlib import Path

from redaction_hooks.verify_schema import (
    ScenarioResult,
    anonymise,
    classify_payload,
    emit_report_json,
    emit_report_md,
    load_golden,
    setup_tmp_project,
    update_golden,
)


def _bash_post_payload() -> dict[str, object]:
    return {
        "session_id": "abc123",
        "transcript_path": "/home/user/.claude/projects/-proj/abc.jsonl",
        "cwd": "/home/user/proj",
        "permission_mode": "auto",
        "effort": {"level": "high"},
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo hi"},
        "tool_response": {
            "stdout": "hi\n",
            "stderr": "",
            "interrupted": False,
            "isImage": False,
            "noOutputExpected": False,
        },
        "tool_use_id": "toolu_xyz",
        "duration_ms": 5,
    }


def test_classify_payload_extracts_post_tool_use_bash() -> None:
    """A known-shape Bash PostToolUse: extractor finds stdout, no drift."""
    cap = classify_payload(_bash_post_payload(), "fake.json", golden={})
    assert cap.event == "PostToolUse"
    assert cap.tool_name == "Bash"
    assert any(f["field_path"] == "stdout" for f in cap.extractor_fields)
    assert cap.drift["extractor_returned_nothing"] is False
    assert cap.drift["new_top_level_keys_vs_corpus"] == []
    assert cap.drift["missing_top_level_keys_vs_corpus"] == []


def test_classify_payload_flags_extractor_returned_nothing() -> None:
    """A future Bash payload that renames `command` to `cmd` produces no
    extractor content (block-only via Phase 1 backstop in production)."""
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"cmd": "echo hi"},  # NOT `command`
    }
    cap = classify_payload(payload, "fake.json", golden={})
    assert cap.extractor_input_content is None
    assert cap.extractor_input_paths == []
    assert cap.drift["extractor_returned_nothing"] is True


def test_classify_payload_diffs_top_level_keys_against_golden() -> None:
    """Drift detects new + missing top-level keys vs the corpus snapshot."""
    payload = _bash_post_payload()
    payload["new_field"] = "added by future CC"
    del payload["duration_ms"]
    golden: dict[tuple[str, str | None], set[str]] = {
        ("PostToolUse", "Bash"): set(_bash_post_payload().keys())
    }
    cap = classify_payload(payload, "fake.json", golden=golden)
    assert "new_field" in cap.drift["new_top_level_keys_vs_corpus"]
    assert "duration_ms" in cap.drift["missing_top_level_keys_vs_corpus"]


def test_classify_payload_ignores_subagent_context_keys_in_drift() -> None:
    """`agent_id` / `agent_type` are decoration CC adds to every hook fired
    inside a subagent (Task tool). They appear regardless of (event, tool),
    so the diff against the non-subagent corpus must NOT flag them as drift
    -- otherwise every subagent-side capture produces noise."""
    payload = _bash_post_payload()
    payload["agent_id"] = "subagent-1"
    payload["agent_type"] = "general-purpose"
    golden: dict[tuple[str, str | None], set[str]] = {
        ("PostToolUse", "Bash"): set(_bash_post_payload().keys())
    }
    cap = classify_payload(payload, "fake.json", golden=golden)
    assert cap.drift["new_top_level_keys_vs_corpus"] == []
    assert cap.drift["missing_top_level_keys_vs_corpus"] == []
    # The keys are still present in top_level_keys (visibility preserved).
    assert "agent_id" in cap.top_level_keys
    assert "agent_type" in cap.top_level_keys


def test_classify_payload_subagent_context_filter_works_in_reverse() -> None:
    """Symmetric case: a corpus that *did* carry agent_id/agent_type (e.g.
    SubagentStop) must not flag them as missing when a payload omits them."""
    payload = _bash_post_payload()
    golden: dict[tuple[str, str | None], set[str]] = {
        ("PostToolUse", "Bash"): set(_bash_post_payload().keys()) | {"agent_id", "agent_type"}
    }
    cap = classify_payload(payload, "fake.json", golden=golden)
    assert cap.drift["missing_top_level_keys_vs_corpus"] == []


def test_classify_payload_does_not_flag_drift_for_non_extractor_events() -> None:
    """InstructionsLoaded / UserPromptSubmit / Stop / *Compact handlers don't
    use the per-tool extractors. The classifier must NOT flag them as drift
    just for having no extractor output -- it should check their event-specific
    entry-point keys instead."""
    cases = [
        {"hook_event_name": "InstructionsLoaded", "file_path": "/x"},
        {"hook_event_name": "UserPromptSubmit", "prompt": "hi"},
        {"hook_event_name": "PreCompact", "transcript_path": "/x"},
        {"hook_event_name": "PostCompact", "transcript_path": "/x"},
        {"hook_event_name": "Stop", "last_assistant_message": "DONE"},
        {"hook_event_name": "Stop", "transcript_path": "/x"},
        {
            "hook_event_name": "SubagentStop",
            "agent_transcript_path": "/x",
            "transcript_path": "/y",
        },
    ]
    for payload in cases:
        cap = classify_payload(payload, "fake.json", golden={})
        assert cap.drift["extractor_returned_nothing"] is False, (
            f"false-positive drift for {payload['hook_event_name']}: {cap.drift!r}"
        )


def test_classify_payload_flags_drift_when_required_keys_all_missing() -> None:
    """A non-extractor event with NONE of its entry-point keys present IS drift."""
    cases = [
        ({"hook_event_name": "InstructionsLoaded"}, ()),  # no file_path
        ({"hook_event_name": "UserPromptSubmit"}, ()),  # no prompt
        ({"hook_event_name": "Stop"}, ()),  # neither last_assistant_message nor transcript_path
    ]
    for payload, _ in cases:
        cap = classify_payload(payload, "fake.json", golden={})
        assert cap.drift["extractor_returned_nothing"] is True, (
            f"missed drift for {payload}: {cap.drift!r}"
        )


def test_anonymise_replaces_home_project_session_tooluse(tmp_path: Path) -> None:
    """The anonymiser replaces all four sensitive substrings, leaves structure intact."""
    home = str(Path.home())
    project = tmp_path / "myproj"
    project.mkdir()
    payload = {
        "session_id": "sess-XYZ",
        "tool_use_id": "tu-ABC",
        "transcript_path": f"{home}/.claude/projects/-myproj/sess-XYZ.jsonl",
        "cwd": str(project),
        "tool_input": {
            "file_path": str(project / "README.md"),
            "nested": [str(project / "x"), "unrelated"],
        },
        "marker": "literal",
    }
    out = anonymise(payload, project)
    assert out["session_id"] == "<SESSION>"
    assert out["tool_use_id"] == "<TOOL_USE>"
    assert "<HOME>" in out["transcript_path"]
    assert "<SESSION>" in out["transcript_path"]
    assert out["cwd"] == "<PROJECT>"
    assert "<PROJECT>" in out["tool_input"]["file_path"]
    assert out["tool_input"]["nested"][0].startswith("<PROJECT>")
    assert out["tool_input"]["nested"][1] == "unrelated"
    assert out["marker"] == "literal"
    # original is untouched (deep copy semantics)
    assert payload["session_id"] == "sess-XYZ"


def test_load_golden_picks_event_and_tool_keys(tmp_path: Path) -> None:
    """The golden loader keys by (event, tool); unknown files are skipped."""
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "PostToolUse-Bash.json").write_text(
        json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Bash", "x": 1})
    )
    (corpus / "PreToolUse-Read.json").write_text(
        json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Read", "y": 2})
    )
    (corpus / "garbage.json").write_text("not json")
    golden = load_golden(corpus)
    assert ("PostToolUse", "Bash") in golden
    assert "x" in golden[("PostToolUse", "Bash")]
    assert ("PreToolUse", "Read") in golden


def test_update_golden_writes_anonymised_per_event_tool(tmp_path: Path) -> None:
    """Golden updater writes one file per (event, tool) with anonymised content."""
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    payload = _bash_post_payload()
    payload["cwd"] = str(project_dir)  # so anonymiser has something to substitute
    cap = classify_payload(payload, "fake.json", golden={})
    cap.raw_payload = payload  # ensure raw_payload is set for update_golden

    corpus = tmp_path / "corpus"
    written = update_golden([cap], project_dir, corpus)
    assert len(written) == 1
    target = corpus / "PostToolUse-Bash.json"
    assert target.exists()
    on_disk = json.loads(target.read_text())
    assert on_disk["cwd"] == "<PROJECT>"
    assert on_disk["session_id"] == "<SESSION>"


def test_emit_report_json_includes_summary_counts() -> None:
    """report.json carries scenario list + per-capture entries + summary tally."""
    cap_ok = classify_payload(_bash_post_payload(), "ok.json", golden={})
    bad_payload = _bash_post_payload()
    bad_payload["tool_response"] = {"unknown_field": "x"}
    cap_drift = classify_payload(bad_payload, "drift.json", golden={})
    sresult = ScenarioResult("bash-success", "...", 0, 1.2, "")
    out = json.loads(emit_report_json([cap_ok, cap_drift], [sresult], "2.1.138"))
    assert out["cc_version"] == "2.1.138"
    assert out["summary"]["events_observed"] == 2
    assert out["summary"]["no_extraction_count"] == 1
    assert out["scenarios"][0]["name"] == "bash-success"


def test_emit_report_md_lists_drift_section_when_present() -> None:
    """Markdown report includes a 'Drift detected' section iff there is drift."""
    cap_ok = classify_payload(_bash_post_payload(), "ok.json", golden={})
    md = emit_report_md([cap_ok], [], "2.1.138")
    assert "## Drift detected" not in md
    assert "## Captures" in md

    bad_payload = _bash_post_payload()
    bad_payload["tool_response"] = {"unknown_field": "x"}
    cap_drift = classify_payload(bad_payload, "drift.json", golden={})
    md_with = emit_report_md([cap_drift], [], "2.1.138")
    assert "## Drift detected" in md_with
    assert "**no fields**" in md_with


def test_setup_tmp_project_writes_settings_and_rules(tmp_path: Path) -> None:
    """Tmp project carries .redaction_rules, .claude/settings.json, README seed
    plus the note.txt / multi.txt seeds for the edit / multiedit scenarios."""
    proj = setup_tmp_project(tmp_path)
    assert (proj / ".redaction_rules").exists()
    assert (proj / "README.md").exists()
    # Seed files for the edit / multiedit scenarios -- each must contain the
    # exact substring the scenario prompt asks the model to replace.
    assert "hello-from-redact-verify" in (proj / "note.txt").read_text()
    multi_content = (proj / "multi.txt").read_text()
    assert "alpha-from-redact-verify" in multi_content
    assert "beta-from-redact-verify" in multi_content
    settings = json.loads((proj / ".claude" / "settings.json").read_text())
    # All events from the installer are registered, with `redact hook` and no matcher.
    assert "PreToolUse" in settings["hooks"]
    assert "PostToolUseFailure" in settings["hooks"]
    for event_entries in settings["hooks"].values():
        for entry in event_entries:
            assert "matcher" not in entry
            assert any(h["command"] == "redact hook" for h in entry["hooks"])
