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

"""Data models for redaction rules and matches."""

from dataclasses import dataclass, field
from typing import Literal

Action = Literal["block", "redact"]
Target = Literal["llm", "tool", "both"]
Replacement = Literal["str", "ip", "email", "hostname"] | str


@dataclass
class Rule:
    """A redaction rule defining a pattern and action."""

    id: str
    pattern: str
    is_regex: bool = True
    hashed: bool = False
    hash_extractor: str | None = None
    action: Action = "block"
    replacement: Replacement | None = None
    target: Target = "both"
    description: str = ""


@dataclass
class Match:
    """A match found by scanning text against rules."""

    rule: Rule
    start: int
    end: int
    text: str
    segment_hash: str | None = None


@dataclass
class ScanResult:
    """Result of scanning text for matches."""

    matches: list[Match] = field(default_factory=list)
    block_reasons: list[str] = field(default_factory=list)
    redacted_text: str | None = None
