"""Loads and validates /rules data files at startup."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from app.rules.conditions import Condition, parse


@dataclass(frozen=True)
class Signal:
    name: str
    field: str
    condition: Condition
    weight: int


@dataclass(frozen=True)
class DeviceType:
    type: str
    default_criticality: str
    level_hint: str
    signals: tuple[Signal, ...]

    @property
    def total_weight(self) -> int:
        return sum(s.weight for s in self.signals)


@dataclass(frozen=True)
class EligibilityRule:
    when: tuple[tuple[str, Condition], ...]
    result: str
    reason: str


@dataclass
class RuleBook:
    rules_dir: Path
    policies: dict[str, dict[str, Any]] = field(default_factory=dict)
    device_types: list[DeviceType] = field(default_factory=list)
    min_confidence: int = 40
    eligibility: list[EligibilityRule] = field(default_factory=list)

    @classmethod
    def load(cls, rules_dir: str | Path) -> "RuleBook":
        root = Path(rules_dir)
        schema = json.loads((root / "schema.json").read_text())
        book = cls(root)
        for path in sorted(root.glob("*.yaml")):
            doc = yaml.safe_load(path.read_text())
            if "policy" in doc:
                jsonschema.validate(doc, schema)
                params = doc.get("parameters") or {}
                for rule in doc["rules"]:
                    cond = parse(rule["condition"])
                    missing = cond.params() - set(params)
                    if missing:
                        raise ValueError(f"{path.name}:{rule['id']} uses undefined parameters {missing}")
                book.policies[doc["policy"]["id"]] = doc
            elif "types" in doc:
                book.min_confidence = int(doc.get("min_confidence", 40))
                for t in doc["types"]:
                    book.device_types.append(DeviceType(
                        t["type"], t["default_criticality"], str(t["level_hint"]),
                        tuple(Signal(s["name"], s["field"], parse(s["condition"]), int(s["weight"]))
                              for s in t["signals"])))
            elif "eligibility" in doc:
                for e in doc["eligibility"]:
                    book.eligibility.append(EligibilityRule(
                        tuple((k, parse(v)) for k, v in (e.get("when") or {}).items()), e["result"], e["reason"]))
        return book
