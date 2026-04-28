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

"""Persistent mapping storage for consistent redaction.

The mapping store guarantees that the same secret is replaced by the same
deterministic string across calls and across processes. Concurrent hook
invocations (PreToolUse + PostToolUse, parallel subagents) serialize their
read-modify-write through an exclusive flock on a sidecar lockfile, and
saves are atomic via tempfile + os.replace. POSIX-only.
"""

import fcntl
import json
import os
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

MAPPINGS_DIR = Path.home() / ".claude" / "redaction_mappings"
PROJECT_MAPPINGS_FILE = ".claude/redaction_mappings.json"

Mappings = dict[str, dict[str, str]]


def _get_mappings_path(project_dir: Path | None = None) -> Path:
    """Get path to mappings file."""
    if project_dir:
        return project_dir / PROJECT_MAPPINGS_FILE
    return MAPPINGS_DIR / "global.json"


def _quarantine_corrupt(path: Path, error: Exception) -> None:
    """Move a corrupt mappings file aside with a `.corrupt-<ts>` suffix.

    Silent erasure of the mapping store would defeat deterministic redaction
    by producing different replacements for previously-seen secrets, so a
    corrupt file is preserved for inspection rather than overwritten.
    """
    quarantine = path.with_name(f"{path.name}.corrupt-{int(time.time())}")
    try:
        path.rename(quarantine)
    except OSError as rename_err:
        sys.stderr.write(
            f"redaction_hooks: corrupt mappings file at {path} "
            f"({error}); could not quarantine: {rename_err}\n"
        )
        return
    sys.stderr.write(f"redaction_hooks: corrupt mappings file moved to {quarantine} ({error})\n")


@contextmanager
def _lock(path: Path) -> Iterator[None]:
    """Hold an exclusive flock on a sidecar lockfile next to `path`.

    The sidecar (rather than locking `path` itself) keeps the lock inode
    stable across the os.replace() that save_mappings performs.
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


def load_mappings(project_dir: Path | None = None) -> Mappings:
    """Load mappings from file. Returns {rule_id: {original: replacement}}.

    A corrupt file is quarantined (see _quarantine_corrupt). I/O errors
    other than corruption return an empty mapping without quarantine.
    """
    path = _get_mappings_path(project_dir)
    if not path.exists():
        return {}
    try:
        with path.open() as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        _quarantine_corrupt(path, e)
        return {}
    except OSError:
        return {}
    if isinstance(data, dict) and isinstance(data.get("mappings"), dict):
        result: Mappings = data["mappings"]
        return result
    return {}


def save_mappings(mappings: Mappings, project_dir: Path | None = None) -> None:
    """Save mappings atomically via tempfile + os.replace.

    Callers that need read-modify-write consistency must hold the lock
    themselves (see get_or_create_mapping); this function does not lock.
    """
    path = _get_mappings_path(project_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"mappings": mappings}, f, indent=2)
        os.replace(tmp_path, path)
    except BaseException:
        with suppress(OSError):
            os.unlink(tmp_path)
        raise


def get_or_create_mapping(
    rule_id: str,
    original: str,
    generator: Callable[[], str],
    project_dir: Path | None = None,
) -> str:
    """Get existing mapping or create and store a new one.

    The full read-check-generate-write cycle runs under an exclusive flock
    so two concurrent hook invocations agree on a single replacement value
    for the same (rule_id, original) pair.
    """
    path = _get_mappings_path(project_dir)
    with _lock(path):
        mappings = load_mappings(project_dir)
        rule_mappings = mappings.setdefault(rule_id, {})
        if original in rule_mappings:
            return rule_mappings[original]
        replacement = generator()
        rule_mappings[original] = replacement
        save_mappings(mappings, project_dir)
        return replacement
