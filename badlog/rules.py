from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Iterable

import yaml
from pydantic import BaseModel, Field


SEVERITIES = {"INFO", "MEDIUM", "HIGH", "CRITICAL"}
CATEGORIES = {
    "WATCHDOG",
    "KERNEL",
    "MEMORY",
    "POWER",
    "ANR",
    "TOMBSTONE",
    "THERMAL",
    "STORAGE",
    "SECURITY",
    "FRAMEWORK",
}


class RuleDefinition(BaseModel):
    name: str
    severity: str
    category: str
    pattern: str
    context_boost: int = 0


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    category: str
    pattern: str
    context_boost: int
    regex: re.Pattern[str]

    @classmethod
    def from_definition(cls, definition: RuleDefinition) -> "Rule":
        if definition.severity not in SEVERITIES:
            raise ValueError(f"Invalid severity: {definition.severity}")
        if definition.category not in CATEGORIES:
            raise ValueError(f"Invalid category: {definition.category}")
        regex = re.compile(definition.pattern, re.IGNORECASE)
        return cls(
            name=definition.name,
            severity=definition.severity,
            category=definition.category,
            pattern=definition.pattern,
            context_boost=definition.context_boost,
            regex=regex,
        )


def load_rules(paths: Iterable[Path]) -> list[Rule]:
    rules: list[Rule] = []
    for path in paths:
        rules.extend(_load_rule_file(path))
    return rules


def _load_rule_file(path: Path) -> list[Rule]:
    if not path.exists():
        raise FileNotFoundError(path)
    content = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        raw = yaml.safe_load(content) or []
    else:
        raw = json.loads(content)
    return [Rule.from_definition(RuleDefinition.model_validate(item)) for item in raw]


def merge_rules(defaults: list[Rule], custom: list[Rule]) -> list[Rule]:
    merged: dict[str, Rule] = {rule.name: rule for rule in defaults}
    for rule in custom:
        merged[rule.name] = rule
    return list(merged.values())


def load_ruleset(default_paths: Iterable[Path], custom_paths: Iterable[Path]) -> list[Rule]:
    defaults = load_rules(default_paths)
    if not custom_paths:
        return defaults
    custom = load_rules(custom_paths)
    return merge_rules(defaults, custom)


def default_rules_path() -> Path:
    try:
        return Path(resources.files("badlog") / "rules" / "default_rules.yaml")
    except (ModuleNotFoundError, AttributeError):
        return Path(__file__).resolve().parent.parent / "rules" / "default_rules.yaml"
