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

"""Claude Code hook entry point.

`run_hook` reads a JSON payload from stdin and dispatches to the per-event
handler in `redaction_hooks.handlers`. Per-tool I/O extractors live in
`redaction_hooks.extractors`; schema-drift signaling lives in
`redaction_hooks.drift`.

The `REDACT_HOOK_DUMP_DIR` env var, when set to a writable directory, causes
the raw stdin payload to be archived under
`<dir>/<event>-<nanos>-<pid>.json` before parsing -- a no-cost diagnostic
primitive used by `redact verify-cc-schema` and ad-hoc payload inspection.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from .handlers import dispatch


def _maybe_dump_payload(raw: str, event: str) -> None:
    """If `$REDACT_HOOK_DUMP_DIR` points at a writable dir, dump the raw stdin
    payload to `<dir>/<event>-<nanos>-<pid>.json`. Best-effort: failures are
    swallowed so debug instrumentation never breaks the hook itself.
    """
    dump_dir = os.environ.get("REDACT_HOOK_DUMP_DIR")
    if not dump_dir:
        return
    try:
        target = Path(dump_dir)
        target.mkdir(parents=True, exist_ok=True)
        name = f"{event or 'Unknown'}-{time.time_ns()}-{os.getpid()}.json"
        (target / name).write_text(raw, encoding="utf-8")
    except OSError as e:
        sys.stderr.write(f"redaction_hooks: REDACT_HOOK_DUMP_DIR write failed: {e}\n")


def run_hook(project_dir: Path | None = None) -> int:
    """Main hook entry point. Reads JSON from stdin, dispatches to handler."""
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"Invalid JSON input: {e}\n")
        _maybe_dump_payload(raw, "InvalidJSON")
        return 1

    event = data.get("hook_event_name", "")
    _maybe_dump_payload(raw, event)
    return dispatch(event, data, project_dir)
