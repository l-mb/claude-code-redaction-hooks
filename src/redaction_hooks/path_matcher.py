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

"""Path-based matching for file access control."""

from fnmatch import fnmatch
from pathlib import Path
from typing import Literal

from .models import Match, Rule


class PathMatcher:
    """Matches file paths against glob patterns in rules."""

    def __init__(self, rules: list[Rule], project_dir: Path | None = None) -> None:
        self.rules = [r for r in rules if r.path_pattern]
        self.project_dir = project_dir or Path.cwd()

    def _normalize_path(self, path: str) -> Path:
        """Normalize a path for matching."""
        # Expand ~ to home directory
        p = Path(path).expanduser()
        if not p.is_absolute():
            p = self.project_dir / p
        try:
            return p.resolve()
        except OSError:
            # Path may not exist, just return absolute form
            return p.absolute()

    def _match_pattern(self, pattern: str, path: Path) -> bool:
        """Match a glob pattern against a normalized path."""
        path_str = str(path)

        # Expand ~ in pattern to match against expanded paths
        if pattern.startswith("~/"):
            pattern = str(Path.home()) + pattern[1:]

        # Try matching against full path
        if fnmatch(path_str, pattern):
            return True

        # Try matching against path relative to project
        try:
            rel_path = path.relative_to(self.project_dir)
            if fnmatch(str(rel_path), pattern):
                return True
        except ValueError:
            pass  # Not relative to project_dir

        # Try matching just the filename
        return bool(fnmatch(path.name, pattern))

    def scan(
        self,
        paths: list[str],
        target: Literal["llm", "tool"],
        tool_name: str | None = None,
    ) -> list[Match]:
        """Scan paths against path-based rules.

        Args:
            paths: List of file paths to check
            target: "llm" for prompts, "tool" for tool inputs/outputs
            tool_name: Filter to rules matching this tool (None = all rules)
        """
        matches: list[Match] = []
        for path in paths:
            normalized = self._normalize_path(path)
            for rule in self.rules:
                if rule.target != "both" and rule.target != target:
                    continue
                if rule.tool is not None and rule.tool != tool_name:
                    continue
                if rule.path_pattern and self._match_pattern(rule.path_pattern, normalized):
                    matches.append(
                        Match(
                            rule=rule,
                            start=0,
                            end=len(path),
                            text=path,
                        )
                    )
        return matches
