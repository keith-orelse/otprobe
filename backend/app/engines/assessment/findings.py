"""Findings lifecycle driven by rule outcomes (docs/STATE_MACHINES.md §5). Deduplicated per asset + rule."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import events
from app.core.audit import Actor
from app.core.clock import utcnow
from app.engines.assessment.engine import RuleOutcome
from app.models import Finding, FindingEvent
from app.workflow.machine import FINDING

ACTIVE = ("OPEN", "REOPENED", "ACCEPTED_RISK")


def _event(session: Session, f: Finding, frm: str | None, to: str, actor: Actor, run_id: str | None,
           reason: str | None = None) -> None:
    session.add(FindingEvent(finding_id=f.id, from_status=frm, to_status=to, run_id=run_id, actor=actor.name,
                             reason=reason))
    events.stage(session, "finding.updated", "finding", f.id, {"status": to, "ruleId": f.rule_id,
                                                               "assetId": f.asset_id})


def transition(session: Session, f: Finding, to: str, actor: Actor, run_id: str | None = None,
               reason: str | None = None, details: dict[str, Any] | None = None) -> None:
    frm = f.status
    FINDING.transition(session, f, to, actor, reason, {"ruleId": f.rule_id, "assetId": f.asset_id, **(details or {})})
    _event(session, f, frm, to, actor, run_id, reason)


def apply_outcome(session: Session, asset_id: str, o: RuleOutcome, source: str, actor: Actor, run_id: str | None
                  ) -> Finding | None:
    """FAIL/WARNING -> open/update/reopen; PASS -> resolve; UNKNOWN -> no change (missing evidence never resolves)."""
    f = session.scalar(select(Finding).where(Finding.asset_id == asset_id, Finding.rule_id == o.rule_id))
    now = utcnow()
    if o.status in ("FAIL", "WARNING"):
        if f is None:
            f = Finding(asset_id=asset_id, rule_id=o.rule_id, title=o.title, severity=o.severity,
                        result_status=o.status, source=source, observed=o.observed, expected=o.expected,
                        references=o.references, remediation=o.remediation, first_seen=now, last_seen=now,
                        last_run_id=run_id)
            FINDING.create(session, f, actor, {"ruleId": o.rule_id, "assetId": asset_id, "severity": o.severity,
                                               "observed": o.observed, "source": source})
            _event(session, f, None, "OPEN", actor, run_id)
            return f
        f.last_seen, f.observed, f.severity, f.result_status = now, o.observed, o.severity, o.status
        f.source, f.last_run_id = source, run_id
        if f.status == "RESOLVED":
            f.reopen_count += 1
            f.resolved_at = None
            transition(session, f, "REOPENED", actor, run_id, "Check failed again (regression)",
                       {"observed": o.observed})
        return f
    if o.status == "PASS" and f is not None and f.status in ACTIVE:
        f.last_seen, f.observed, f.resolved_at, f.last_run_id = now, o.observed, now, run_id
        transition(session, f, "RESOLVED", actor, run_id, "Check passes", {"observed": o.observed})
    return f


def open_event_finding(session: Session, asset_id: str, rule: dict[str, Any], observed: Any, actor: Actor) -> Finding:
    """Findings raised by events (e.g. NET-ROGUE-001 from discovery) rather than evidence."""
    o = RuleOutcome(rule_id=rule["id"], title=rule["title"], status=rule["on_fail"]["status"],
                    severity=rule["on_fail"].get("severity", rule["severity"]), weight_severity=rule["severity"],
                    evidence_path=rule["evidence"], observed=observed, expected=rule.get("expected", ""),
                    message=None, references=list(rule.get("references", [])), remediation=rule.get("remediation"))
    return apply_outcome(session, asset_id, o, "DISCOVERY", actor, None)
