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

"""Configuration loading for redaction rules."""

from pathlib import Path
from typing import Any

import yaml

from .models import Action, Rule, Target

VALID_ACTIONS = {"block", "redact", "warn"}
VALID_TARGETS = {"llm", "tool", "both"}

PROJECT_RULES_FILE = ".redaction_rules"
GLOBAL_RULES_DIR = Path.home() / ".claude"
GLOBAL_RULES_FILE = GLOBAL_RULES_DIR / ".redaction_rules"


def _parse_rule(data: dict[str, Any]) -> Rule:
    """Parse a rule dictionary into a Rule object."""
    return Rule(
        id=data["id"],
        pattern=data.get("pattern"),
        path_pattern=data.get("path_pattern"),
        is_regex=data.get("is_regex", True),
        hashed=data.get("hashed", False),
        hash_extractor=data.get("hash_extractor"),
        action=data.get("action", "block"),
        replacement=data.get("replacement"),
        target=data.get("target", "both"),
        tool=data.get("tool"),
        description=data.get("description", ""),
    )


def load_rules_file(path: Path) -> list[Rule]:
    """Load rules from a YAML file."""
    if not path.exists():
        return []
    with path.open() as f:
        data = yaml.safe_load(f)
    if not data or "rules" not in data:
        return []
    return [_parse_rule(r) for r in data["rules"]]


def save_rules_file(path: Path, rules: list[Rule]) -> None:
    """Save rules to a YAML file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "rules": [
            {
                k: v
                for k, v in {
                    "id": r.id,
                    "pattern": r.pattern,
                    "path_pattern": r.path_pattern,
                    "is_regex": r.is_regex if not r.is_regex else None,
                    "hashed": r.hashed if r.hashed else None,
                    "hash_extractor": r.hash_extractor,
                    "action": r.action if r.action != "block" else None,
                    "replacement": r.replacement,
                    "target": r.target if r.target != "both" else None,
                    "tool": r.tool,
                    "description": r.description if r.description else None,
                }.items()
                if v is not None
            }
            for r in rules
        ]
    }
    with path.open("w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def load_rules(project_dir: Path | None = None) -> list[Rule]:
    """Load and merge rules from global and project configs.

    Project rules override global rules with the same id.
    """
    global_rules = load_rules_file(GLOBAL_RULES_FILE)
    if project_dir is None:
        project_dir = Path.cwd()
    project_rules = load_rules_file(project_dir / PROJECT_RULES_FILE)

    # Index by id, project overrides global
    rules_by_id: dict[str, Rule] = {}
    for rule in global_rules:
        rules_by_id[rule.id] = rule
    for rule in project_rules:
        rules_by_id[rule.id] = rule

    return list(rules_by_id.values())


def get_rules_path(global_: bool = False, project_dir: Path | None = None) -> Path:
    """Get the path to the rules file."""
    if global_:
        return GLOBAL_RULES_FILE
    if project_dir is None:
        project_dir = Path.cwd()
    return project_dir / PROJECT_RULES_FILE


def add_hashed_rule(
    secret: str,
    rule_id: str,
    description: str = "",
    hash_extractor: str = r"\b\w{4,}\b",
    action: Action = "block",
    target: Target = "both",
    global_: bool = False,
    project_dir: Path | None = None,
) -> Rule:
    """Add a new hashed rule to the rules file."""
    from .matcher import hash_text

    path = get_rules_path(global_=global_, project_dir=project_dir)
    rules = load_rules_file(path)

    # Remove existing rule with same id
    rules = [r for r in rules if r.id != rule_id]

    new_rule = Rule(
        id=rule_id,
        pattern=hash_text(secret),
        hashed=True,
        hash_extractor=hash_extractor,
        action=action,
        target=target,
        description=description,
    )
    rules.append(new_rule)
    save_rules_file(path, rules)
    return new_rule


def _validate_rule(rule: dict[str, Any], index: int, seen_ids: set[str]) -> list[str]:
    """Validate a single rule dict, return list of errors."""
    import re

    errors: list[str] = []
    prefix = f"Rule {index + 1}"

    if "id" not in rule:
        errors.append(f"{prefix}: missing required field 'id'")
    else:
        rule_id = rule["id"]
        prefix = f"Rule '{rule_id}'"
        if rule_id in seen_ids:
            errors.append(f"{prefix}: duplicate id")
        seen_ids.add(rule_id)

    has_pattern = "pattern" in rule
    has_path_pattern = "path_pattern" in rule

    if not has_pattern and not has_path_pattern:
        errors.append(f"{prefix}: must have 'pattern' or 'path_pattern'")

    if has_pattern and rule.get("is_regex", True) and not rule.get("hashed", False):
        try:
            re.compile(rule["pattern"])
        except re.error as e:
            errors.append(f"{prefix}: invalid regex pattern: {e}")

    if has_path_pattern and not isinstance(rule["path_pattern"], str):
        errors.append(f"{prefix}: path_pattern must be a string")

    if "hash_extractor" in rule:
        try:
            re.compile(rule["hash_extractor"])
        except re.error as e:
            errors.append(f"{prefix}: invalid hash_extractor regex: {e}")

    if "action" in rule and rule["action"] not in VALID_ACTIONS:
        valid = ", ".join(sorted(VALID_ACTIONS))
        errors.append(f"{prefix}: invalid action '{rule['action']}' (must be: {valid})")

    if "target" in rule and rule["target"] not in VALID_TARGETS:
        valid = ", ".join(sorted(VALID_TARGETS))
        errors.append(f"{prefix}: invalid target '{rule['target']}' (must be: {valid})")

    return errors


def validate_rules_file(path: Path) -> list[str]:
    """Validate a rules file, return list of error messages (empty if valid)."""
    if not path.exists():
        return []

    try:
        with path.open() as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"YAML syntax error: {e}"]

    if data is None:
        return []

    if not isinstance(data, dict):
        return ["Invalid format: expected a mapping with 'rules' key"]

    if "rules" not in data:
        return []

    if not isinstance(data["rules"], list):
        return ["Invalid format: 'rules' must be a list"]

    errors: list[str] = []
    seen_ids: set[str] = set()
    for i, rule in enumerate(data["rules"]):
        if not isinstance(rule, dict):
            errors.append(f"Rule {i + 1}: must be a mapping")
            continue
        errors.extend(_validate_rule(rule, i, seen_ids))

    return errors
