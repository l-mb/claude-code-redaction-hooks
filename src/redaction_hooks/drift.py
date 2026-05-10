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

"""Schema-drift signaling for hook handlers.

CC's hook payload schema is undocumented in detail and drifts between releases.
Handlers call into this module when (a) the per-tool extractor returned nothing
but a recursive walk found a match anyway, or (b) a required top-level key is
missing while configured rules would otherwise have fired. Both signals end up
in the audit log under action='schema-drift' so operators can grep for them
with `redact audit since 7d | jq 'select(.action=="schema-drift")'`.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .audit import log_event
from .models import Match


def audit_stale_extractor(
    hook: str,
    matches: list[Match],
    *,
    tool: str | None = None,
    tool_use_id: str | None = None,
    project_dir: Path | None = None,
) -> None:
    """Drift signal: per-tool extractor returned nothing but a recursive walk
    over the payload still found a rule match. The CC payload shape for this
    tool may have moved underneath us. Surfaces in audit + stderr.
    """
    if not matches:
        return
    rule_ids = sorted({m.rule.id for m in matches})
    log_event(
        hook=hook,
        action="schema-drift",
        rule_ids=rule_ids,
        tool=tool,
        tool_use_id=tool_use_id,
        project_dir=project_dir,
    )
    sys.stderr.write(
        f"schema-drift: {hook}/{tool or '<n/a>'} matched only via recursive walk "
        f"(rules {rule_ids}); per-tool extractor may be stale\n"
    )


def audit_missing_key(
    hook: str,
    key: str,
    *,
    project_dir: Path | None = None,
) -> None:
    """Drift signal: a handler couldn't proceed because a required top-level
    input key was missing/empty, even though configured rules WOULD have fired
    if it had been present. Uses a synthetic rule_id `missing-key:<key>` so
    operators can grep/filter cleanly.
    """
    sys.stderr.write(
        f"schema-drift: {hook} received payload missing required key '{key}'; handler skipped\n"
    )
    log_event(
        hook=hook,
        action="schema-drift",
        rule_ids=[f"missing-key:{key}"],
        project_dir=project_dir,
    )
