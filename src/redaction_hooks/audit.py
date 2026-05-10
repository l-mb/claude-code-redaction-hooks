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

"""Append-only audit log for hook decisions.

Each block / redact / warn outcome is recorded as a single JSON line so that
auditors can answer "did rule X fire in the last 30 days?" without scraping
stderr. Appends and prune-rewrites both hold an exclusive flock on a
sidecar lockfile so a prune cannot race a concurrent append into the
about-to-be-replaced file.

The matched secret text is NEVER recorded -- only the rule IDs that matched.
"""

import fcntl
import json
import os
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

PROJECT_AUDIT_LOG = ".claude/redaction_audit.log"
GLOBAL_AUDIT_LOG = Path.home() / ".claude" / "redaction_audit.log"


def _audit_path(project_dir: Path | None = None) -> Path:
    if project_dir is not None:
        return project_dir / PROJECT_AUDIT_LOG
    return GLOBAL_AUDIT_LOG


@contextmanager
def _lock(path: Path) -> Iterator[None]:
    """Hold an exclusive flock on a sidecar lockfile next to `path`.

    The sidecar (rather than locking `path` itself) keeps the lock inode
    stable across the os.replace() that prune_entries performs.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def log_event(
    hook: str,
    action: str,
    rule_ids: list[str],
    *,
    tool: str | None = None,
    tool_use_id: str | None = None,
    project_dir: Path | None = None,
) -> None:
    """Append a single audit entry. Failures are swallowed so a broken
    audit log never breaks a hook invocation."""
    if not rule_ids:
        return
    entry: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        "hook": hook,
        "action": action,
        "rule_ids": rule_ids,
    }
    if tool is not None:
        entry["tool"] = tool
    if tool_use_id is not None:
        entry["tool_use_id"] = tool_use_id
    line = (json.dumps(entry, separators=(",", ":")) + "\n").encode("utf-8")
    path = _audit_path(project_dir)
    try:
        with _lock(path):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                with suppress(OSError):
                    os.write(fd, line)
            finally:
                os.close(fd)
    except OSError as e:
        sys.stderr.write(f"redaction_hooks: audit log open failed: {e}\n")


def read_entries(project_dir: Path | None = None) -> list[dict[str, Any]]:
    """Read all audit entries. Skips lines that fail to parse."""
    path = _audit_path(project_dir)
    if not path.exists():
        return []
    entries: list[dict[str, Any]] = []
    with path.open() as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                entries.append(obj)
    return entries


def prune_entries(before_seconds: int, project_dir: Path | None = None) -> int:
    """Delete audit entries older than `before_seconds`. Returns count removed.

    Entries with missing or unparseable `ts` are kept (we can't age them
    safely). Lines that fail JSON decoding are kept verbatim too.
    """
    if before_seconds < 0:
        raise ValueError("before_seconds must be non-negative")
    path = _audit_path(project_dir)
    if not path.exists():
        return 0
    cutoff = datetime.now(UTC) - timedelta(seconds=before_seconds)
    removed = 0
    with _lock(path):
        kept_lines: list[str] = []
        with path.open() as f:
            for raw in f:
                stripped = raw.strip()
                if not stripped:
                    continue
                try:
                    obj = json.loads(stripped)
                except json.JSONDecodeError:
                    kept_lines.append(stripped)
                    continue
                ts_str = obj.get("ts") if isinstance(obj, dict) else None
                if not isinstance(ts_str, str):
                    kept_lines.append(stripped)
                    continue
                try:
                    entry_time = datetime.fromisoformat(ts_str)
                except ValueError:
                    kept_lines.append(stripped)
                    continue
                if entry_time >= cutoff:
                    kept_lines.append(stripped)
                else:
                    removed += 1
        if removed == 0:
            return 0
        fd, tmp_path = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "w") as out:
                for line in kept_lines:
                    out.write(line + "\n")
            os.replace(tmp_path, path)
        except BaseException:
            with suppress(OSError):
                os.unlink(tmp_path)
            raise
    return removed


_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(text: str) -> int:
    """Parse `<int><s|m|h|d|w>` (e.g. "30m", "1h", "7d") into seconds."""
    text = text.strip().lower()
    if not text or text[-1] not in _DURATION_UNITS:
        raise ValueError(f"invalid duration {text!r}; expected e.g. '30m', '1h', '7d'")
    try:
        n = int(text[:-1])
    except ValueError as e:
        raise ValueError(f"invalid duration {text!r}: {e}") from e
    if n < 0:
        raise ValueError(f"invalid duration {text!r}: must be non-negative")
    return n * _DURATION_UNITS[text[-1]]
