"""Data-driven classification and agent eligibility (rules/classification.yaml, rules/eligibility.yaml)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.rules.book import RuleBook
from app.rules.conditions import MISSING, ConditionTypeError, evaluate, resolve_path


@dataclass(frozen=True)
class Classification:
    type: str
    confidence: int
    evidence: list[dict[str, Any]]
    default_criticality: str
    level_hint: str

    def as_dict(self) -> dict[str, Any]:
        return {"type": self.type, "confidence": self.confidence, "evidence": self.evidence}


def _safe_eval(condition, value) -> bool:
    if value is MISSING and condition.disjuncts[0][0].op != "empty":
        return False
    try:
        return evaluate(condition, value)
    except ConditionTypeError:
        return False


def _summarize(condition, value: Any) -> Any:
    if isinstance(value, list):
        matching = [v for v in value if _safe_eval(condition, [v]) or _safe_eval(condition, v)]
        shown = matching or value
        return shown[:3] if len(shown) > 1 else (shown[0] if shown else [])
    return value


def classify(doc: dict[str, Any], book: RuleBook) -> Classification | None:
    best: Classification | None = None
    best_weight = -1
    for t in book.device_types:
        evidence, matched = [], 0
        for sig in t.signals:
            value = resolve_path(doc, sig.field)
            if _safe_eval(sig.condition, value):
                matched += sig.weight
                evidence.append({"signal": sig.name, "field": sig.field, "value": _summarize(sig.condition, value),
                                 "weight": sig.weight})
        if not t.total_weight:
            continue
        confidence = round(100 * matched / t.total_weight)
        if confidence < book.min_confidence:
            continue
        if best is None or confidence > best.confidence or (confidence == best.confidence and matched > best_weight):
            best = Classification(t.type, confidence, evidence, t.default_criticality, t.level_hint)
            best_weight = matched
    return best


def eligibility(doc: dict[str, Any], book: RuleBook) -> tuple[str, str]:
    for rule in book.eligibility:
        if all(_safe_eval(cond, resolve_path(doc, path)) for path, cond in rule.when):
            return rule.result, rule.reason
    return "UNKNOWN", "Run an agentless probe to determine eligibility."
