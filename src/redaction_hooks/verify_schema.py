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

"""Live verification harness for Claude Code hook payload shapes.

Drives `claude -p` headlessly through scripted scenarios while capturing
every hook payload via `REDACT_HOOK_DUMP_DIR`. For each capture, runs the
named-field extractors from hooks.py and diffs the top-level keys against
a committed corpus. Emits a structured JSON report plus a Markdown summary
that can be fed back to a future Claude session for analysis.
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .extractors import (
    get_tool_input_content,
    get_tool_input_paths,
    iter_output_fields,
)


@dataclass(frozen=True)
class Scenario:
    name: str
    prompt: str
    max_turns: int = 3


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        "bash-success",
        "Run `echo hello-from-redact-verify` once. Reply only DONE.",
        max_turns=2,
    ),
    Scenario(
        "bash-fail",
        "Run `ls /no-such-path-redact-verify` once. Reply only DONE.",
        max_turns=2,
    ),
    Scenario(
        "read-file",
        "Read README.md and reply with only its first heading.",
        max_turns=2,
    ),
    Scenario(
        "grep",
        "Use the Grep tool with pattern 'rules' against README.md. Reply only DONE.",
        max_turns=2,
    ),
    Scenario(
        "glob",
        "Use the Glob tool with pattern '*.md'. Reply only DONE.",
        max_turns=2,
    ),
    Scenario(
        "write",
        (
            "Use the Write tool to create file `out.txt` with the single line "
            "`hello-from-redact-verify`. Reply only DONE."
        ),
        max_turns=2,
    ),
    # Edit/MultiEdit require the file to be Read first in-session, so each of
    # these scenarios also exercises PreToolUse/PostToolUse for Read -- bonus
    # coverage at no extra cost.
    Scenario(
        "edit",
        (
            "Use the Edit tool on `note.txt` to replace the exact string "
            "`hello-from-redact-verify` with `world-from-redact-verify`. Reply only DONE."
        ),
        max_turns=3,
    ),
    # In CC 2.1.138 MultiEdit is a *deferred* tool: the model has to call
    # ToolSearch before it becomes invocable. Our prompt therefore reliably
    # produces a ToolSearch capture (which we want for coverage); whether
    # MultiEdit itself fires depends on whether ToolSearch finds it. If it
    # doesn't, the model falls back to two Edit calls, so we still exercise
    # the Edit path. Bumped to max_turns=4 to give room for ToolSearch +
    # Read + edit(s) + final reply.
    Scenario(
        "multiedit-deferred",
        (
            "Use the MultiEdit tool on `multi.txt` with two edits: replace "
            "`alpha-from-redact-verify` with `ALPHA-from-redact-verify`, then "
            "replace `beta-from-redact-verify` with `BETA-from-redact-verify`. "
            "Reply only DONE."
        ),
        max_turns=4,
    ),
    Scenario(
        "task-subagent",
        (
            "Use the Task tool to delegate the prompt 'list cwd files and reply DONE' "
            "to a general-purpose subagent. Reply only DONE when the subagent finishes."
        ),
        max_turns=3,
    ),
)


@dataclass
class Capture:
    file: str
    event: str
    tool_name: str | None
    top_level_keys: list[str]
    tool_input_keys: list[str]
    tool_response_keys_or_type: list[str] | str | None
    extractor_fields: list[dict[str, str]]
    extractor_input_content: str | None
    extractor_input_paths: list[str]
    drift: dict[str, Any]
    raw_payload: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass
class ScenarioResult:
    name: str
    prompt: str
    exit_code: int
    duration_s: float
    stderr_tail: str


def detect_cc_version(claude_bin: str = "claude", timeout: float = 5.0) -> str:
    """Return `claude --version` output (first whitespace-separated token) or 'unknown'."""
    try:
        proc = subprocess.run(
            [claude_bin, "--version"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "unknown"
    out = (proc.stdout or proc.stderr).strip()
    return out.split()[0] if out else "unknown"


def setup_tmp_project(parent: Path) -> Path:
    """Build a self-contained tmp project: rules + settings + seed README."""
    # Lazy import to avoid circular dep with cli.py.
    from .cli import _HOOK_EVENT_MATCHERS, REDACT_HOOK_COMMAND

    proj = parent / "project"
    (proj / ".claude").mkdir(parents=True)
    (proj / ".redaction_rules").write_text(
        "rules:\n"
        "  - id: harness-warn\n"
        "    pattern: 'redact-verify-canary-XYZ'\n"
        "    action: warn\n"
        "    description: Harmless canary so the hook dispatcher exercises every event.\n"
    )
    settings = {
        "hooks": {
            event: [{"hooks": [{"type": "command", "command": REDACT_HOOK_COMMAND}]}]
            for event in _HOOK_EVENT_MATCHERS
        }
    }
    (proj / ".claude" / "settings.json").write_text(json.dumps(settings, indent=2))
    (proj / "README.md").write_text("# Sample\n\nSome text mentioning rules so grep has a hit.\n")
    # Seed files for the edit / multiedit scenarios. Each scenario is
    # self-contained: never relies on a prior scenario's mutations.
    (proj / "note.txt").write_text("hello-from-redact-verify\n")
    (proj / "multi.txt").write_text(
        "alpha-from-redact-verify\nbeta-from-redact-verify\n",
    )
    return proj


def run_scenario(
    scenario: Scenario,
    project_dir: Path,
    dump_dir: Path,
    *,
    claude_bin: str = "claude",
    scenario_timeout: float = 120.0,
) -> ScenarioResult:
    """Invoke `claude -p` for one scenario; return exit + duration + stderr tail."""
    env = os.environ.copy()
    env["REDACT_HOOK_DUMP_DIR"] = str(dump_dir)
    env["CLAUDE_PROJECT_DIR"] = str(project_dir)
    cmd = [
        claude_bin,
        "-p",
        scenario.prompt,
        "--dangerously-skip-permissions",
        "--max-turns",
        str(scenario.max_turns),
        "--no-session-persistence",
    ]
    start = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=project_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=scenario_timeout,
            check=False,
        )
        return ScenarioResult(
            name=scenario.name,
            prompt=scenario.prompt,
            exit_code=proc.returncode,
            duration_s=time.time() - start,
            stderr_tail=(proc.stderr or "").strip()[-500:],
        )
    except subprocess.TimeoutExpired:
        return ScenarioResult(
            name=scenario.name,
            prompt=scenario.prompt,
            exit_code=-1,
            duration_s=time.time() - start,
            stderr_tail=f"timeout after {scenario_timeout}s",
        )


def _preview(s: str, n: int = 80) -> str:
    s = s.replace("\n", "\\n")
    return s[:n] + ("..." if len(s) > n else "")


def load_golden(corpus_dir: Path) -> dict[tuple[str, str | None], set[str]]:
    """Load top-level key sets from the committed corpus, keyed by (event, tool)."""
    golden: dict[tuple[str, str | None], set[str]] = {}
    if not corpus_dir.exists():
        return golden
    for path in corpus_dir.glob("*.json"):
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        event = data.get("hook_event_name")
        tool = data.get("tool_name")
        if event:
            golden[(event, tool)] = set(data.keys())
    return golden


def classify_capture(
    file_path: Path,
    golden: dict[tuple[str, str | None], set[str]] | None = None,
) -> Capture:
    """Parse a captured payload, run the extractors, diff vs golden corpus."""
    payload = json.loads(file_path.read_text())
    return classify_payload(payload, str(file_path), golden or {})


# Events whose handlers use the per-tool extractors (`get_tool_input_*`
# and `iter_output_fields`). Other events have their own entry-point keys
# checked directly in REQUIRED_KEYS_BY_EVENT below.
_EXTRACTOR_EVENTS = frozenset({"PreToolUse", "PostToolUse", "PostToolUseFailure"})

# Top-level keys CC attaches to *any* hook fired inside a subagent (Task tool).
# Their presence/absence is a function of execution context, not schema, so
# filter them out of the corpus-vs-payload diff -- otherwise every subagent-side
# Bash/Read/Grep/etc. capture would flag spurious drift against the
# non-subagent corpus fixtures.
_SUBAGENT_CONTEXT_KEYS = frozenset({"agent_id", "agent_type"})

# For every non-extractor event, name the top-level keys the handler walks.
# Order matters: the first match wins (so e.g. Stop prefers the inline
# `last_assistant_message` and falls back to `transcript_path`).
_REQUIRED_KEYS_BY_EVENT: dict[str, tuple[str, ...]] = {
    "UserPromptSubmit": ("prompt",),
    "InstructionsLoaded": ("file_path",),
    "PreCompact": ("transcript_path",),
    "PostCompact": ("transcript_path",),
    "Stop": ("last_assistant_message", "transcript_path"),
    "SubagentStop": ("last_assistant_message", "agent_transcript_path", "transcript_path"),
}


def classify_payload(
    payload: dict[str, Any],
    file_label: str,
    golden: dict[tuple[str, str | None], set[str]],
) -> Capture:
    event = payload.get("hook_event_name", "Unknown")
    tool_name = payload.get("tool_name")
    top_keys = sorted(payload.keys())
    tool_input = payload.get("tool_input", {})
    tool_input_keys = sorted(tool_input.keys()) if isinstance(tool_input, dict) else []
    tool_response = payload.get("tool_response")
    tr_keys: list[str] | str | None
    if isinstance(tool_response, dict):
        tr_keys = sorted(tool_response.keys())
    elif tool_response is None:
        tr_keys = None
    else:
        tr_keys = type(tool_response).__name__

    extractor_fields: list[dict[str, str]] = []
    extractor_input_content: str | None = None
    extractor_input_paths: list[str] = []

    if (
        isinstance(tool_name, str)
        and isinstance(tool_input, dict)
        and event in ("PreToolUse", "PostToolUseFailure")
    ):
        content = get_tool_input_content(tool_name, tool_input)
        extractor_input_content = _preview(content) if content else None
        extractor_input_paths = get_tool_input_paths(tool_name, tool_input)
    if isinstance(tool_name, str) and event == "PostToolUse" and tool_response is not None:
        for path, content in iter_output_fields(tool_name, tool_response):
            extractor_fields.append({"field_path": path, "preview": _preview(content)})

    # An "extractor returned nothing" finding only makes sense for events that
    # actually use the per-tool extractors. For others (Stop, UserPromptSubmit,
    # InstructionsLoaded, PreCompact, PostCompact) we instead check that at
    # least one of the handler's documented entry-point keys is present.
    extractor_returned_nothing = False
    if event in _EXTRACTOR_EVENTS:
        extractor_returned_nothing = (
            not extractor_fields and not extractor_input_content and not extractor_input_paths
        )
    elif event in _REQUIRED_KEYS_BY_EVENT:
        required = _REQUIRED_KEYS_BY_EVENT[event]
        extractor_returned_nothing = not any(payload.get(k) for k in required)

    golden_keys = golden.get((event, tool_name), set())
    new_keys = sorted(set(top_keys) - golden_keys - _SUBAGENT_CONTEXT_KEYS) if golden_keys else []
    missing_keys = (
        sorted(golden_keys - set(top_keys) - _SUBAGENT_CONTEXT_KEYS) if golden_keys else []
    )
    drift = {
        "extractor_returned_nothing": extractor_returned_nothing,
        "new_top_level_keys_vs_corpus": new_keys,
        "missing_top_level_keys_vs_corpus": missing_keys,
    }
    return Capture(
        file=file_label,
        event=event,
        tool_name=tool_name,
        top_level_keys=top_keys,
        tool_input_keys=tool_input_keys,
        tool_response_keys_or_type=tr_keys,
        extractor_fields=extractor_fields,
        extractor_input_content=extractor_input_content,
        extractor_input_paths=extractor_input_paths,
        drift=drift,
        raw_payload=payload,
    )


def anonymise(payload: dict[str, Any], project_dir: Path) -> dict[str, Any]:
    """Deep-copy `payload`, replacing $HOME / project / session_id / tool_use_id
    with placeholders. Conservative: only touches string leaves."""
    home = str(Path.home())
    proj = str(Path(project_dir).resolve())
    session_id = payload.get("session_id")
    tool_use_id = payload.get("tool_use_id")

    def sub(s: str) -> str:
        if proj and proj in s:
            s = s.replace(proj, "<PROJECT>")
        if home and home in s:
            s = s.replace(home, "<HOME>")
        if isinstance(session_id, str) and session_id and session_id in s:
            s = s.replace(session_id, "<SESSION>")
        if isinstance(tool_use_id, str) and tool_use_id and tool_use_id in s:
            s = s.replace(tool_use_id, "<TOOL_USE>")
        return s

    def walk(o: Any) -> Any:
        if isinstance(o, str):
            return sub(o)
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        return o

    return walk(payload)  # type: ignore[no-any-return]


def emit_report_json(
    captures: Iterable[Capture],
    scenarios_run: Iterable[ScenarioResult],
    cc_version: str,
) -> str:
    captures = list(captures)
    scenarios_run = list(scenarios_run)
    drift_count = sum(
        1
        for c in captures
        if c.drift["extractor_returned_nothing"]
        or c.drift["new_top_level_keys_vs_corpus"]
        or c.drift["missing_top_level_keys_vs_corpus"]
    )
    return json.dumps(
        {
            "cc_version": cc_version,
            "ran_at": datetime.now(UTC).isoformat(),
            "scenarios": [dataclasses.asdict(s) for s in scenarios_run],
            "captures": [
                {k: v for k, v in dataclasses.asdict(c).items() if k != "raw_payload"}
                for c in captures
            ],
            "summary": {
                "events_observed": len(captures),
                "drift_count": drift_count,
                "no_extraction_count": sum(
                    1 for c in captures if c.drift["extractor_returned_nothing"]
                ),
            },
        },
        indent=2,
    )


def emit_report_md(
    captures: Iterable[Capture],
    scenarios_run: Iterable[ScenarioResult],
    cc_version: str,
) -> str:
    captures = list(captures)
    scenarios_run = list(scenarios_run)
    lines: list[str] = [
        "# CC schema verify report",
        "",
        f"- CC version: `{cc_version}`",
        f"- Ran: {datetime.now(UTC).isoformat()}",
        f"- Captures: {len(captures)}",
        "",
        "## Scenarios",
        "",
        "| Scenario | Exit | Duration | Stderr tail |",
        "|---|---|---|---|",
    ]
    for s in scenarios_run:
        tail = s.stderr_tail.replace("|", "\\|").replace("\n", " ")[:80]
        lines.append(f"| {s.name} | {s.exit_code} | {s.duration_s:.1f}s | {tail} |")
    lines.extend(
        [
            "",
            "## Captures",
            "",
            "| Event | Tool | Extractor | Drift |",
            "|---|---|---|---|",
        ]
    )
    for c in captures:
        ext_status = "ok" if not c.drift["extractor_returned_nothing"] else "**no fields**"
        drift_bits = []
        if c.drift["new_top_level_keys_vs_corpus"]:
            drift_bits.append(f"+keys {c.drift['new_top_level_keys_vs_corpus']}")
        if c.drift["missing_top_level_keys_vs_corpus"]:
            drift_bits.append(f"-keys {c.drift['missing_top_level_keys_vs_corpus']}")
        drift_str = "; ".join(drift_bits) or "—"
        lines.append(f"| {c.event} | {c.tool_name or '—'} | {ext_status} | {drift_str} |")

    drifted = [
        c
        for c in captures
        if c.drift["extractor_returned_nothing"]
        or c.drift["new_top_level_keys_vs_corpus"]
        or c.drift["missing_top_level_keys_vs_corpus"]
    ]
    if drifted:
        lines.extend(["", "## Drift detected", ""])
        for c in drifted:
            lines.append(f"### {c.event}/{c.tool_name or '<n/a>'}  (`{Path(c.file).name}`)")
            lines.append(f"- top_level_keys: `{c.top_level_keys}`")
            lines.append(f"- tool_input_keys: `{c.tool_input_keys}`")
            lines.append(f"- tool_response_keys_or_type: `{c.tool_response_keys_or_type}`")
            lines.append(f"- extractor_fields: `{c.extractor_fields}`")
            lines.append(f"- extractor_input_content: `{c.extractor_input_content}`")
            lines.append(f"- drift: `{c.drift}`")
            lines.append("")
    return "\n".join(lines) + "\n"


def update_golden(captures: Iterable[Capture], project_dir: Path, corpus_dir: Path) -> list[str]:
    """Write the most recent (event, tool) capture to the corpus, anonymised."""
    by_key: dict[tuple[str, str | None], Capture] = {}
    for c in captures:
        by_key[(c.event, c.tool_name)] = c
    corpus_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for (event, tool), cap in by_key.items():
        anonymised = anonymise(cap.raw_payload, project_dir)
        name = f"{event}-{tool}.json" if tool else f"{event}.json"
        target = corpus_dir / name
        target.write_text(json.dumps(anonymised, indent=2) + "\n")
        written.append(str(target))
    return written


def _default_corpus_dir() -> Path:
    return Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures" / "cc-payloads"


def run(
    *,
    report_dir: Path,
    keep_tmp: bool = False,
    update_golden_flag: bool = False,
    claude_bin: str = "claude",
    corpus_dir: Path | None = None,
) -> int:
    """Top-level entry: drive scenarios, classify captures, emit reports.

    Returns:
      0 = no drift detected
      1 = drift detected (extractor returned nothing OR keys diff vs corpus)
      2 = harness error (claude binary missing, version probe failed)
    """
    if corpus_dir is None:
        corpus_dir = _default_corpus_dir()
    cc_version = detect_cc_version(claude_bin)
    if cc_version == "unknown":
        sys.stderr.write(
            f"redact verify-cc-schema: cannot probe `{claude_bin} --version`; "
            "is the binary on PATH?\n"
        )
        return 2

    parent = Path(tempfile.mkdtemp(prefix="redact-verify-"))
    try:
        project_dir = setup_tmp_project(parent)
        dump_dir = parent / "dump"
        dump_dir.mkdir()

        scenario_results: list[ScenarioResult] = []
        for scenario in SCENARIOS:
            scenario_results.append(
                run_scenario(scenario, project_dir, dump_dir, claude_bin=claude_bin)
            )

        golden = load_golden(corpus_dir)
        captures: list[Capture] = []
        for path in sorted(dump_dir.glob("*.json")):
            try:
                captures.append(classify_capture(path, golden))
            except (OSError, json.JSONDecodeError) as e:
                sys.stderr.write(f"WARN: cannot classify {path}: {e}\n")

        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / "report.json").write_text(
            emit_report_json(captures, scenario_results, cc_version)
        )
        (report_dir / "report.md").write_text(
            emit_report_md(captures, scenario_results, cc_version)
        )
        sys.stderr.write(
            f"verify-cc-schema: {len(captures)} captures across "
            f"{len(scenario_results)} scenarios; reports in {report_dir}\n"
        )

        if update_golden_flag:
            written = update_golden(captures, project_dir, corpus_dir)
            sys.stderr.write(f"verify-cc-schema: updated {len(written)} golden fixture(s)\n")
            for w in written:
                sys.stderr.write(f"  {w}\n")

        drift_count = sum(
            1
            for c in captures
            if c.drift["extractor_returned_nothing"]
            or c.drift["new_top_level_keys_vs_corpus"]
            or c.drift["missing_top_level_keys_vs_corpus"]
        )
        return 1 if drift_count > 0 else 0
    finally:
        if keep_tmp:
            sys.stderr.write(f"verify-cc-schema: tmp project kept at {parent}\n")
        else:
            shutil.rmtree(parent, ignore_errors=True)
