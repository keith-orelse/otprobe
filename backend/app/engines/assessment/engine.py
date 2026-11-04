"""Rule engine: data-driven evaluation, scoring and evidence diffing (docs/RULES.md). Pure functions, no I/O."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.rules.conditions import (
    MISSING,
    ConditionSyntaxError,
    ConditionTypeError,
    evaluate,
    parse,
    resolve_operand,
    resolve_path,
)

WEIGHTS = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1}
CREDIT = {"PASS": 1.0, "WARNING": 0.5, "FAIL": 0.0}
DEGRADED = {"FAIL", "WARNING"}


@dataclass(frozen=True)
class RuleOutcome:
    rule_id: str
    title: str
    status: str            # PASS | FAIL | WARNING | UNKNOWN
    severity: str          # severity of the finding it would raise (on_fail.severity, else rule.severity)
    weight_severity: str   # rule.severity: scoring weight basis
    evidence_path: str
    observed: Any
    expected: str
    message: str | None
    references: list[str]
    remediation: str | None
    rule_error: bool = False


def _applies(selector: dict[str, str] | None, doc: dict[str, Any], params: dict[str, Any]) -> bool:
    for path, cond in (selector or {}).items():
        value = resolve_path(doc, path)
        if value is MISSING:
            return False
        try:
            if not evaluate(cond, value, params):
                return False
        except ConditionTypeError:
            return False
    return True


def policy_applies(policy: dict[str, Any], doc: dict[str, Any]) -> bool:
    return _applies(policy["policy"].get("applies_to"), doc, policy.get("parameters") or {})


def _offending(cond_text: str, value: Any, params: dict[str, Any]) -> Any:
    """For a failed list rule (e.g. 'not intersects $unauthorized_software'), report only the offending items."""
    if not isinstance(value, list):
        return value
    cond = parse(cond_text)
    if len(cond.disjuncts) != 1 or len(cond.disjuncts[0]) != 1:
        return value
    clause = cond.disjuncts[0][0]
    if clause.op == "intersects" and clause.negate:
        try:
            operand = resolve_operand(clause.operand, params)
        except ConditionSyntaxError:
            return value
        return [v for v in value if v in operand]
    return value


def evaluate_policy(policy: dict[str, Any], evidence: dict[str, Any], source: str) -> list[RuleOutcome]:
    """Evaluation order per rule: applicability -> missing evidence -> type check -> condition."""
    params = policy.get("parameters") or {}
    out: list[RuleOutcome] = []
    for rule in policy["rules"]:
        if source not in rule.get("sources", ["DEEP_AGENT"]):
            continue
        if not _applies(rule.get("applies_to"), evidence, params):
            continue
        path = rule["evidence"]
        value = resolve_path(evidence, path)
        on_fail = rule["on_fail"]
        common = dict(rule_id=rule["id"], title=rule["title"], weight_severity=rule["severity"], evidence_path=path,
                      expected=rule.get("expected", rule["condition"]), references=list(rule.get("references", [])),
                      remediation=rule.get("remediation"))
        if value is MISSING:
            miss = rule.get("on_missing", {"status": "UNKNOWN"})
            out.append(RuleOutcome(status=miss["status"], severity=miss.get("severity", rule["severity"]),
                                   observed=None, message=f"evidence '{path}' not present", **common))
            continue
        try:
            passed = evaluate(parse(rule["condition"]), value, params)
        except (ConditionTypeError, ConditionSyntaxError) as exc:
            out.append(RuleOutcome(status="UNKNOWN", severity=rule["severity"], observed=value,
                                   message=f"type mismatch: {exc}", rule_error=True, **common))
            continue
        if passed:
            out.append(RuleOutcome(status="PASS", severity=on_fail.get("severity", rule["severity"]), observed=value,
                                   message=None, **common))
        else:
            out.append(RuleOutcome(status=on_fail["status"], severity=on_fail.get("severity", rule["severity"]),
                                   observed=_offending(rule["condition"], value, params), message=None, **common))
    return out


def score(outcomes: list[RuleOutcome]) -> tuple[float | None, dict[str, int]]:
    """Weighted pass rate over PASS/WARNING/FAIL; UNKNOWN excluded and counted separately."""
    counts = {"pass": 0, "fail": 0, "warning": 0, "unknown": 0}
    total = achieved = 0.0
    for o in outcomes:
        counts[o.status.lower()] += 1
        if o.status in CREDIT:
            w = WEIGHTS[o.weight_severity]
            total += w
            achieved += w * CREDIT[o.status]
    return (round(100 * achieved / total, 1) if total else None), counts


def flatten(doc: Any, prefix: str = "") -> dict[str, Any]:
    """Leaf paths of an evidence document; lists are compared as whole values."""
    if isinstance(doc, dict):
        out: dict[str, Any] = {}
        for k, v in doc.items():
            out.update(flatten(v, f"{prefix}.{k}" if prefix else k))
        return out
    return {prefix: doc}


IGNORED_DIFF_PREFIXES = ("collectedAt", "agent.uptime_sec", "hardware.uptime_sec", "collectors")


def evidence_diff(before: dict[str, Any] | None, after: dict[str, Any]) -> list[tuple[str, Any, Any]]:
    a, b = flatten(before or {}), flatten(after)
    changes = []
    for path in sorted(set(a) | set(b)):
        if path.startswith(IGNORED_DIFF_PREFIXES):
            continue
        if a.get(path, MISSING) != b.get(path, MISSING):
            changes.append((path, a.get(path), b.get(path)))
    return changes


def is_drift(previous: str | None, current: str) -> bool:
    return previous == "PASS" and current in DEGRADED
