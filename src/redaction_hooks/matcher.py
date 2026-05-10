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
import signal
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Literal

from .models import Match, Rule

DEFAULT_REGEX_TIMEOUT_SECONDS = 1


class RegexTimeoutError(Exception):
    """Raised when a regex match exceeds the configured per-rule timeout."""


@contextmanager
def regex_timeout(seconds: int) -> Iterator[None]:
    """Bound the runtime of regex operations to `seconds`.

    Uses SIGALRM, which only works on POSIX in the main thread. On other
    platforms or in worker threads this becomes a no-op -- the regex still
    runs, just without enforcement.
    """
    if (
        seconds <= 0
        or not hasattr(signal, "SIGALRM")
        or threading.current_thread() is not threading.main_thread()
    ):
        yield
        return

    def _handler(_signum: int, _frame: object) -> None:
        raise RegexTimeoutError

    old_handler = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def hash_text(text: str) -> str:
    """Compute SHA-256 hash of text."""
    return hashlib.sha256(text.encode()).hexdigest()


class PatternMatcher:
    """Scans text against a list of redaction rules."""

    def __init__(
        self, rules: list[Rule], *, timeout_seconds: int = DEFAULT_REGEX_TIMEOUT_SECONDS
    ) -> None:
        # Only include rules that have a content pattern
        self.rules = [r for r in rules if r.pattern]
        self._compiled: dict[str, re.Pattern[str]] = {}
        self.timeout_seconds = timeout_seconds
        self.last_timeouts: list[str] = []

    def _get_pattern(self, rule: Rule) -> re.Pattern[str]:
        """Get compiled regex pattern for a rule."""
        assert rule.pattern is not None  # Guaranteed by filtering in __init__
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
        self.last_timeouts = []
        matches: list[Match] = []
        for rule in self.rules:
            if rule.target != "both" and rule.target != target:
                continue
            if rule.tool is not None and rule.tool != tool_name:
                continue
            try:
                with regex_timeout(self.timeout_seconds):
                    if rule.hashed:
                        matches.extend(self._match_hashed(rule, text))
                    else:
                        matches.extend(self._match_plain(rule, text))
            except RegexTimeoutError:
                self.last_timeouts.append(rule.id)
                sys.stderr.write(
                    f"redaction_hooks: regex for rule '{rule.id}' exceeded "
                    f"{self.timeout_seconds}s -- skipping\n"
                )
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
