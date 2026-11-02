"""Declarative state machines. Every transition is validated, audited and published (after commit)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from app.core import audit, events
from app.core.audit import Actor
from app.core.errors import ProblemError


@dataclass(frozen=True)
class StateMachine:
    label: str          # "Discovery job"
    entity_kind: str    # "discovery" (also the SSE topic)
    initial: str
    create_event: str
    transitions: dict[tuple[str, str], str]   # (from, to) -> audit event name

    @property
    def states(self) -> set[str]:
        return {self.initial} | {s for edge in self.transitions for s in edge}

    def allowed(self, frm: str, to: str) -> bool:
        return (frm, to) in self.transitions

    def create(self, session: Session, entity: Any, actor: Actor, details: dict[str, Any] | None = None) -> None:
        entity.status = self.initial
        session.add(entity)
        session.flush()
        audit.record(session, actor, self.create_event, self.entity_kind, entity.id, details)
        events.stage(session, f"{self.entity_kind}.status", self.entity_kind, entity.id, {"status": self.initial})

    def transition(self, session: Session, entity: Any, to: str, actor: Actor, reason: str | None = None,
                   details: dict[str, Any] | None = None) -> None:
        frm = entity.status
        event_name = self.transitions.get((frm, to))
        if event_name is None:
            raise ProblemError(409, "invalid-state-transition", "Invalid state transition",
                               f"{self.label} {entity.id} cannot go from {frm} to {to}")
        entity.status = to
        payload = {"from": frm, "to": to, **({"reason": reason} if reason else {}), **(details or {})}
        audit.record(session, actor, event_name, self.entity_kind, entity.id, payload)
        events.stage(session, f"{self.entity_kind}.status", self.entity_kind, entity.id,
                     {"status": to, "from": frm, **({"reason": reason} if reason else {})})


DISCOVERY = StateMachine(
    "Discovery job", "discovery", "QUEUED", "DISCOVERY_REQUESTED",
    {
        ("QUEUED", "RUNNING"): "DISCOVERY_STARTED",
        ("QUEUED", "CANCELLED"): "DISCOVERY_CANCELLED",
        ("RUNNING", "COMPLETED"): "DISCOVERY_COMPLETED",
        ("RUNNING", "FAILED"): "DISCOVERY_FAILED",
        ("RUNNING", "CANCELLED"): "DISCOVERY_CANCELLED",
    },
)

PROBE = StateMachine(
    "Probe run", "probe", "QUEUED", "PROBE_REQUESTED",
    {
        ("QUEUED", "RUNNING"): "PROBE_STARTED",
        ("QUEUED", "FAILED"): "PROBE_FAILED",
        ("RUNNING", "COMPLETED"): "PROBE_COMPLETED",
        ("RUNNING", "PARTIAL"): "PROBE_COMPLETED",
        ("RUNNING", "FAILED"): "PROBE_FAILED",
    },
)

MACHINES = {m.entity_kind: m for m in (DISCOVERY, PROBE)}
