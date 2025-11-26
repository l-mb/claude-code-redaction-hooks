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

"""Redaction and blocking actions for matched patterns."""

import hashlib
from pathlib import Path

from .mappings import get_or_create_mapping
from .models import Match, ScanResult


def _hash_short(text: str) -> str:
    """Generate short hash for replacement tokens."""
    return hashlib.sha256(text.encode()).hexdigest()[:8]


def _generate_ip(original: str) -> str:
    """Generate deterministic fake IP from original text."""
    h = hashlib.sha256(original.encode()).digest()
    return f"10.{h[0]}.{h[1]}.{h[2]}"


def _generate_email(original: str) -> str:
    """Generate deterministic fake email from original text."""
    return f"redacted-{_hash_short(original)}@example.com"


def _generate_hostname(original: str) -> str:
    """Generate deterministic fake hostname from original text."""
    return f"host-{_hash_short(original)}.internal"


def _get_replacement(match: Match, project_dir: Path | None = None) -> str:
    """Get replacement string for a match, using persistent mappings."""
    replacement_type = match.rule.replacement

    def generator() -> str:
        if replacement_type is None:
            return "[REDACTED]"
        if replacement_type == "ip":
            return _generate_ip(match.text)
        if replacement_type == "email":
            return _generate_email(match.text)
        if replacement_type == "hostname":
            return _generate_hostname(match.text)
        return str(replacement_type)

    return get_or_create_mapping(match.rule.id, match.text, generator, project_dir)


def apply_actions(text: str, matches: list[Match], project_dir: Path | None = None) -> ScanResult:
    """Apply redaction/blocking actions to text based on matches.

    Returns ScanResult with:
    - block_reasons: list of reasons if any blocking rules matched
    - redacted_text: text with redactions applied (None if blocked)
    - matches: the original matches
    """
    if not matches:
        return ScanResult(matches=[], redacted_text=text)

    block_reasons: list[str] = []
    redact_matches: list[Match] = []

    for match in matches:
        if match.rule.action == "block":
            reason = f"[{match.rule.id}] {match.rule.description or 'Pattern matched'}"
            block_reasons.append(reason)
        else:
            redact_matches.append(match)

    if block_reasons:
        return ScanResult(matches=matches, block_reasons=block_reasons)

    # Apply redactions in reverse order to preserve positions
    result = text
    for match in sorted(redact_matches, key=lambda m: m.start, reverse=True):
        replacement = _get_replacement(match, project_dir)
        result = result[: match.start] + replacement + result[match.end :]

    return ScanResult(matches=matches, redacted_text=result)
