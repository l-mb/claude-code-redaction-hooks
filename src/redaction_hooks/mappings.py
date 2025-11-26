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

"""Persistent mapping storage for consistent redaction."""

import json
from collections.abc import Callable
from pathlib import Path

MAPPINGS_DIR = Path.home() / ".claude" / "redaction_mappings"
PROJECT_MAPPINGS_FILE = ".claude/redaction_mappings.json"

Mappings = dict[str, dict[str, str]]


def _get_mappings_path(project_dir: Path | None = None) -> Path:
    """Get path to mappings file."""
    if project_dir:
        return project_dir / PROJECT_MAPPINGS_FILE
    return MAPPINGS_DIR / "global.json"


def load_mappings(project_dir: Path | None = None) -> Mappings:
    """Load mappings from file. Returns {rule_id: {original: replacement}}."""
    path = _get_mappings_path(project_dir)
    if not path.exists():
        return {}
    try:
        with path.open() as f:
            data = json.load(f)
            if isinstance(data, dict) and "mappings" in data:
                result: Mappings = data["mappings"]
                return result
            return {}
    except (json.JSONDecodeError, OSError):
        return {}


def save_mappings(mappings: Mappings, project_dir: Path | None = None) -> None:
    """Save mappings to file."""
    path = _get_mappings_path(project_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump({"mappings": mappings}, f, indent=2)


def get_or_create_mapping(
    rule_id: str,
    original: str,
    generator: Callable[[], str],
    project_dir: Path | None = None,
) -> str:
    """Get existing mapping or create and store a new one."""
    mappings = load_mappings(project_dir)
    rule_mappings = mappings.setdefault(rule_id, {})

    if original in rule_mappings:
        return rule_mappings[original]

    replacement = generator()
    rule_mappings[original] = replacement
    save_mappings(mappings, project_dir)
    return replacement
