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

DEPLOYMENT = StateMachine(
    "Deployment", "deployment", "REQUESTED", "DEPLOYMENT_REQUESTED",
    {
        ("REQUESTED", "PENDING_APPROVAL"): "DEPLOYMENT_SUBMITTED",
        ("PENDING_APPROVAL", "APPROVED"): "DEPLOYMENT_APPROVED",
        ("PENDING_APPROVAL", "REJECTED"): "DEPLOYMENT_REJECTED",
        ("APPROVED", "PRECHECK_RUNNING"): "PRECHECK_STARTED",
        ("PRECHECK_RUNNING", "PRECHECK_PASSED"): "PRECHECK_PASSED",
        ("PRECHECK_RUNNING", "PRECHECK_FAILED"): "PRECHECK_FAILED",
        ("PRECHECK_FAILED", "PRECHECK_RUNNING"): "PRECHECK_RETRIED",
        ("PRECHECK_PASSED", "PRECHECK_RUNNING"): "PRECHECK_RETRIED",
        ("PRECHECK_PASSED", "DEPLOYING"): "DEPLOYMENT_STARTED",
        ("DEPLOYING", "ENROLLING"): "AGENT_INSTALLED",
        ("DEPLOYING", "FAILED"): "DEPLOYMENT_FAILED",
        ("ENROLLING", "COMPLETED"): "DEPLOYMENT_COMPLETED",
        ("ENROLLING", "FAILED"): "DEPLOYMENT_FAILED",
    },
)

# NOT_INSTALLED is the implicit state of an asset without an active agent row (docs/STATE_MACHINES §3);
# an agents row is created when the INSTALL step succeeds, starting in ENROLLING.
AGENT = StateMachine(
    "Agent", "agent", "ENROLLING", "AGENT_REGISTERED",
    {
        ("ENROLLING", "ONLINE"): "AGENT_ENROLLED",
        ("ENROLLING", "ERROR"): "AGENT_ENROLLMENT_FAILED",
        ("ONLINE", "STALE"): "AGENT_STALE",
        ("STALE", "OFFLINE"): "AGENT_OFFLINE",
        ("STALE", "ONLINE"): "AGENT_RECOVERED",
        ("OFFLINE", "ONLINE"): "AGENT_RECOVERED",
        ("ONLINE", "REMOVING"): "AGENT_REMOVAL_STARTED",
        ("STALE", "REMOVING"): "AGENT_REMOVAL_STARTED",
        ("OFFLINE", "REMOVING"): "AGENT_REMOVAL_STARTED",
        ("ERROR", "REMOVING"): "AGENT_REMOVAL_STARTED",
        ("REMOVING", "REMOVED"): "AGENT_REMOVED",
        ("REMOVING", "ERROR"): "AGENT_ERROR",
    },
)

APPROVAL = StateMachine(
    "Approval", "approval", "PENDING", "APPROVAL_REQUESTED",
    {
        ("PENDING", "APPROVED"): "APPROVAL_GRANTED",
        ("PENDING", "REJECTED"): "APPROVAL_DENIED",
        ("PENDING", "EXPIRED"): "APPROVAL_EXPIRED",
    },
)

# Declared now (section 8); the rollback workflow that drives it is Phase 5.
REMOVAL = StateMachine(
    "Removal", "removal", "REQUESTED", "REMOVAL_REQUESTED",
    {
        ("REQUESTED", "APPROVED"): "REMOVAL_APPROVED",
        ("REQUESTED", "REJECTED"): "REMOVAL_REJECTED",
        ("APPROVED", "RUNNING"): "REMOVAL_STARTED",
        ("RUNNING", "COMPLETED"): "ROLLBACK_COMPLETED",
        ("RUNNING", "FAILED"): "ROLLBACK_FAILED",
        ("FAILED", "RUNNING"): "REMOVAL_RETRIED",
    },
)

FINDING = StateMachine(
    "Finding", "finding", "OPEN", "FINDING_OPENED",
    {
        ("OPEN", "RESOLVED"): "FINDING_RESOLVED",
        ("REOPENED", "RESOLVED"): "FINDING_RESOLVED",
        ("RESOLVED", "REOPENED"): "FINDING_REOPENED",
        ("OPEN", "ACCEPTED_RISK"): "FINDING_RISK_ACCEPTED",
        ("REOPENED", "ACCEPTED_RISK"): "FINDING_RISK_ACCEPTED",
        ("ACCEPTED_RISK", "RESOLVED"): "FINDING_RESOLVED",
        ("ACCEPTED_RISK", "OPEN"): "FINDING_RISK_REVOKED",
    },
)

ASSESSMENT = StateMachine(
    "Assessment run", "assessment", "QUEUED", "ASSESSMENT_REQUESTED",
    {
        ("QUEUED", "RUNNING"): "ASSESSMENT_STARTED",
        ("QUEUED", "CANCELLED"): "ASSESSMENT_CANCELLED",
        ("QUEUED", "EVALUATED"): "ASSESSMENT_EVALUATED",   # agentless runs are evaluated immediately
        ("RUNNING", "EVALUATED"): "ASSESSMENT_EVALUATED",
        ("RUNNING", "FAILED"): "ASSESSMENT_FAILED",
        ("RUNNING", "TIMED_OUT"): "ASSESSMENT_TIMED_OUT",
        ("RUNNING", "CANCELLED"): "ASSESSMENT_CANCELLED",
    },
)

TASK = StateMachine(
    "Agent task", "task", "QUEUED", "TASK_QUEUED",
    {
        ("QUEUED", "DISPATCHED"): "TASK_DISPATCHED",
        ("QUEUED", "CANCELLED"): "TASK_CANCELLED",
        ("DISPATCHED", "COMPLETED"): "TASK_COMPLETED",
        ("DISPATCHED", "FAILED"): "TASK_FAILED",
        ("DISPATCHED", "TIMED_OUT"): "TASK_TIMED_OUT",
        ("DISPATCHED", "CANCELLED"): "TASK_CANCELLED",
    },
)

MACHINES = {m.entity_kind: m for m in (DISCOVERY, PROBE, DEPLOYMENT, AGENT, APPROVAL, REMOVAL, FINDING, ASSESSMENT,
                                       TASK)}
