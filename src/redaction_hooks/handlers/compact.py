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

"""PreCompact + PostCompact handlers.

Both events scan the transcript via `_scan_transcript`. PreCompact can
block compaction; PostCompact is observe-only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from ..config import load_rules
from ..drift import audit_missing_key
from ..extractors import walk_strings
from ..matcher import PatternMatcher
from ..models import Match
from ._common import audit_matches, audit_timeouts, build_decision_block_response


def _scan_transcript(
    transcript_path: str, project_dir: Path | None
) -> tuple[list[Match], list[str], str | None]:
    """Scan every string in every JSONL line of `transcript_path` against llm rules.

    Returns (matches, regex_timeouts, error). When llm rules are empty or the
    transcript is unreadable, matches is empty and an error string explains.
    """
    rules = load_rules(project_dir)
    llm_rules = [r for r in rules if r.target in ("llm", "both")]
    if not llm_rules:
        return [], [], None
    try:
        with Path(transcript_path).open(encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        return [], [], f"cannot read transcript {transcript_path}: {e}"

    matcher = PatternMatcher(llm_rules)
    matches: list[Match] = []
    timeouts: list[str] = []
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        for text in walk_strings(obj):
            matches.extend(matcher.scan(text, "llm"))
            timeouts.extend(matcher.last_timeouts)
    return matches, timeouts, None


def handle_pre_compact(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle PreCompact hook - scan the transcript before context compaction.

    PreCompact passes `transcript_path` (a JSONL session log) on stdin rather
    than the messages inline. Compaction summarizes the transcript into a new
    context message; secrets present in earlier turns can leak into the summary
    even if they were blocked at the input layer. This handler scans the
    transcript and blocks compaction if a block-action rule matches.

    PreCompact cannot rewrite the summary, so warn rules audit-and-warn while
    redact rules surface as redact-skipped audits + stderr.
    """
    transcript_path = data.get("transcript_path", "")
    trigger = data.get("trigger", "unknown")

    if not transcript_path:
        # Phase 2(b)
        rules = load_rules(project_dir)
        llm_rules = [r for r in rules if r.target in ("llm", "both")]
        if llm_rules:
            audit_missing_key("PreCompact", "transcript_path", project_dir=project_dir)
        json.dump({"continue": True}, sys.stdout)
        return 0

    all_matches, timeouts, err = _scan_transcript(transcript_path, project_dir)
    if err is not None:
        sys.stderr.write(f"PreCompact: {err}\n")
        json.dump({"continue": True}, sys.stdout)
        return 0

    audit_timeouts("PreCompact", timeouts, project_dir=project_dir)

    if not all_matches:
        json.dump({"continue": True}, sys.stdout)
        return 0

    block_matches = [m for m in all_matches if m.rule.action == "block"]
    warn_matches = [m for m in all_matches if m.rule.action == "warn"]
    redact_matches = [m for m in all_matches if m.rule.action == "redact"]

    if warn_matches:
        ids = sorted({m.rule.id for m in warn_matches})
        sys.stderr.write(f"PreCompact warning: rules {ids} matched in transcript\n")
        audit_matches("PreCompact", "warn", warn_matches, project_dir=project_dir)

    if redact_matches:
        ids = sorted({m.rule.id for m in redact_matches})
        sys.stderr.write(
            f"PreCompact warning: redact rules {ids} matched but cannot rewrite "
            "the compacted summary; consider blocking instead\n"
        )
        audit_matches("PreCompact", "redact-skipped", redact_matches, project_dir=project_dir)

    if block_matches:
        ids = sorted({m.rule.id for m in block_matches})
        audit_matches("PreCompact", "block", block_matches, project_dir=project_dir)
        reason = f"rules {ids} matched in transcript (trigger={trigger})"
        json.dump(build_decision_block_response("PreCompact", [reason]), sys.stdout)
        sys.stderr.write(f"PreCompact blocked: rules {ids} matched\n")
        # exit 0 + JSON: see user_prompt_submit.py for the rationale.
        return 0

    json.dump({"continue": True}, sys.stdout)
    return 0


def handle_post_compact(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle PostCompact - audit any rule matches in the post-compaction transcript.

    PostCompact has no decision control (per docs): compaction has already
    happened. This handler only audits + warns to surface that the summary
    contains content rules would have flagged.
    """
    transcript_path = data.get("transcript_path", "")
    trigger = data.get("trigger", "unknown")

    if not transcript_path:
        # Phase 2(b)
        rules = load_rules(project_dir)
        llm_rules = [r for r in rules if r.target in ("llm", "both")]
        if llm_rules:
            audit_missing_key("PostCompact", "transcript_path", project_dir=project_dir)
        json.dump({"continue": True}, sys.stdout)
        return 0

    all_matches, timeouts, err = _scan_transcript(transcript_path, project_dir)
    if err is not None:
        sys.stderr.write(f"PostCompact: {err}\n")
        json.dump({"continue": True}, sys.stdout)
        return 0

    audit_timeouts("PostCompact", timeouts, project_dir=project_dir)
    if not all_matches:
        json.dump({"continue": True}, sys.stdout)
        return 0

    rule_ids = sorted({m.rule.id for m in all_matches})
    sys.stderr.write(
        f"PostCompact warning: rules {rule_ids} matched in compacted transcript "
        f"(trigger={trigger})\n"
    )
    # Observe-only event: compaction has already produced the summary; redact
    # cannot rewrite it. Surface as redact-skipped per the README contract.
    for rule_action, audit_action in (
        ("warn", "warn"),
        ("block", "block"),
        ("redact", "redact-skipped"),
    ):
        action_matches = [m for m in all_matches if m.rule.action == rule_action]
        if action_matches:
            audit_matches("PostCompact", audit_action, action_matches, project_dir=project_dir)

    json.dump({"continue": True}, sys.stdout)
    return 0
