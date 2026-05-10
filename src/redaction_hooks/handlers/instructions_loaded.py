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

"""InstructionsLoaded handler -- scan a loaded CLAUDE.md / .claude/rules/*.md."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from ..config import load_rules
from ..drift import audit_missing_key
from ..extractors import SPILLED_FILE_BYTES_CAP
from ..matcher import PatternMatcher
from ._common import audit_matches, audit_timeouts


def handle_instructions_loaded(data: dict[str, Any], project_dir: Path | None = None) -> int:
    """Handle InstructionsLoaded - scan a loaded CLAUDE.md / rules file for secrets.

    Fires when Claude Code loads a memory file (CLAUDE.md, `.claude/rules/*.md`).
    The hook has no decision control per the docs, so this handler only reports
    matches via stderr + audit. Detects committed secrets in rule files and
    user-scope memory.
    """
    file_path = data.get("file_path", "")
    memory_type = data.get("memory_type", "Unknown")
    load_reason = data.get("load_reason", "unknown")

    if not file_path:
        # Phase 2(b): the entry-point key went missing.
        rules = load_rules(project_dir)
        llm_rules = [r for r in rules if r.target in ("llm", "both")]
        if llm_rules:
            audit_missing_key("InstructionsLoaded", "file_path", project_dir=project_dir)
        json.dump({"continue": True}, sys.stdout)
        return 0

    rules = load_rules(project_dir)
    llm_rules = [r for r in rules if r.target in ("llm", "both")]
    if not llm_rules:
        json.dump({"continue": True}, sys.stdout)
        return 0

    p = Path(file_path).expanduser()
    try:
        with p.open("rb") as f:
            data_bytes = f.read(SPILLED_FILE_BYTES_CAP + 1)
    except OSError as e:
        sys.stderr.write(f"InstructionsLoaded: cannot read {file_path}: {e}\n")
        json.dump({"continue": True}, sys.stdout)
        return 0
    if len(data_bytes) > SPILLED_FILE_BYTES_CAP:
        data_bytes = data_bytes[:SPILLED_FILE_BYTES_CAP]
    content = data_bytes.decode("utf-8", errors="replace")

    matcher = PatternMatcher(llm_rules)
    matches = matcher.scan(content, "llm")
    audit_timeouts("InstructionsLoaded", matcher.last_timeouts, project_dir=project_dir)

    if not matches:
        json.dump({"continue": True}, sys.stdout)
        return 0

    rule_ids = sorted({m.rule.id for m in matches})
    sys.stderr.write(
        f"InstructionsLoaded warning: rules {rule_ids} matched in {memory_type} "
        f"file {file_path} (load_reason={load_reason})\n"
    )
    # Observe-only event: redact-action match cannot rewrite a memory file
    # already loaded by CC. Surface as redact-skipped per the README contract.
    for rule_action, audit_action in (
        ("warn", "warn"),
        ("block", "block"),
        ("redact", "redact-skipped"),
    ):
        action_matches = [m for m in matches if m.rule.action == rule_action]
        if action_matches:
            audit_matches(
                "InstructionsLoaded", audit_action, action_matches, project_dir=project_dir
            )

    json.dump({"continue": True}, sys.stdout)
    return 0
