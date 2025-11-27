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

"""Pattern matching engine for redaction rules."""

import hashlib
import re
from typing import Literal

from .models import Match, Rule


def hash_text(text: str) -> str:
    """Compute SHA-256 hash of text."""
    return hashlib.sha256(text.encode()).hexdigest()


class PatternMatcher:
    """Scans text against a list of redaction rules."""

    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules
        self._compiled: dict[str, re.Pattern[str]] = {}

    def _get_pattern(self, rule: Rule) -> re.Pattern[str]:
        """Get compiled regex pattern for a rule."""
        if rule.id not in self._compiled:
            if rule.is_regex:
                self._compiled[rule.id] = re.compile(rule.pattern)
            else:
                self._compiled[rule.id] = re.compile(re.escape(rule.pattern))
        return self._compiled[rule.id]

    def _get_extractor(self, rule: Rule) -> re.Pattern[str] | None:
        """Get compiled hash extractor pattern."""
        if not rule.hash_extractor:
            return None
        key = f"{rule.id}_extractor"
        if key not in self._compiled:
            self._compiled[key] = re.compile(rule.hash_extractor)
        return self._compiled[key]

    def scan(
        self, text: str, target: Literal["llm", "tool"], tool_name: str | None = None
    ) -> list[Match]:
        """Scan text and return all matches for applicable rules.

        Args:
            text: Content to scan
            target: "llm" for prompts, "tool" for tool inputs/outputs
            tool_name: Filter to rules matching this tool (None = all rules)
        """
        matches: list[Match] = []
        for rule in self.rules:
            if rule.target != "both" and rule.target != target:
                continue
            if rule.tool is not None and rule.tool != tool_name:
                continue
            if rule.hashed:
                matches.extend(self._match_hashed(rule, text))
            else:
                matches.extend(self._match_plain(rule, text))
        return matches

    def _match_plain(self, rule: Rule, text: str) -> list[Match]:
        """Match using regex or fixed string pattern."""
        pattern = self._get_pattern(rule)
        return [
            Match(rule=rule, start=m.start(), end=m.end(), text=m.group())
            for m in pattern.finditer(text)
        ]

    def _match_hashed(self, rule: Rule, text: str) -> list[Match]:
        """Match by hashing extracted segments and comparing to stored hash."""
        extractor = self._get_extractor(rule)
        if not extractor:
            return []
        matches: list[Match] = []
        for m in extractor.finditer(text):
            segment = m.group()
            segment_hash = hash_text(segment)
            if segment_hash == rule.pattern:
                matches.append(
                    Match(
                        rule=rule,
                        start=m.start(),
                        end=m.end(),
                        text=segment,
                        segment_hash=segment_hash,
                    )
                )
        return matches
