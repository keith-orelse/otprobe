"""Append-only, hash-chained audit trail."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core import events
from app.core.clock import utcnow
from app.core.correlation import get_correlation_id
from app.models import AuditEvent

GENESIS = "0" * 64


@dataclass(frozen=True)
class Actor:
    type: str  # USER | AGENT | SYSTEM | SIMULATOR
    name: str
    id: str | None = None


ANONYMOUS = Actor("USER", "anonymous")  # replaced by authenticated users in Phase 3


def system(name: str) -> Actor:
    return Actor("SYSTEM", name)


def _digest(prev_hash: str, row: dict[str, Any]) -> str:
    canonical = json.dumps(row, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


def _row(e: AuditEvent) -> dict[str, Any]:
    return {"seq": e.seq, "at": e.at.isoformat(), "actorType": e.actor_type, "actorId": e.actor_id,
            "actorName": e.actor_name, "action": e.action, "entityKind": e.entity_kind, "entityId": e.entity_id,
            "correlationId": e.correlation_id, "details": e.details}


def record(session: Session, actor: Actor, action: str, entity_kind: str, entity_id: str | None,
           details: dict[str, Any] | None = None) -> AuditEvent:
    last = session.execute(select(AuditEvent.seq, AuditEvent.hash).order_by(AuditEvent.seq.desc()).limit(1)).first()
    seq, prev_hash = (last[0] + 1, last[1]) if last else (1, GENESIS)
    evt = AuditEvent(seq=seq, at=utcnow(), actor_type=actor.type, actor_id=actor.id, actor_name=actor.name,
                     action=action, entity_kind=entity_kind, entity_id=entity_id,
                     correlation_id=get_correlation_id(), details=details or {}, prev_hash=prev_hash)
    evt.hash = _digest(prev_hash, _row(evt))
    session.add(evt)
    session.flush()
    events.stage(session, "audit.event", entity_kind, entity_id, {"action": action, "seq": seq})
    return evt


def verify(session: Session) -> dict[str, Any]:
    prev = GENESIS
    count = 0
    for e in session.scalars(select(AuditEvent).order_by(AuditEvent.seq)):
        count += 1
        if e.prev_hash != prev or _digest(prev, _row(e)) != e.hash:
            return {"valid": False, "events": count, "brokenAtSeq": e.seq}
        prev = e.hash
    last = session.scalar(select(func.max(AuditEvent.seq)))
    return {"valid": True, "events": count, "lastSeq": last}
