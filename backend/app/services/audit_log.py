from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import schemas
from app.models import AuditEvent
from app.services.common import paginate


def list_events(session: Session, limit: int, cursor: str | None, action: str | None, entity_id: str | None,
                correlation_id: str | None, actor: str | None) -> schemas.Page:
    stmt = select(AuditEvent).order_by(AuditEvent.seq.desc())
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if entity_id:
        stmt = stmt.where(AuditEvent.entity_id == entity_id)
    if correlation_id:
        stmt = stmt.where(AuditEvent.correlation_id == correlation_id)
    if actor:
        stmt = stmt.where(AuditEvent.actor_name == actor)
    rows, nxt, total = paginate(session, stmt, limit, cursor)
    return schemas.Page[schemas.AuditEvent](items=[schemas.AuditEvent.model_validate(r) for r in rows],
                                            next_cursor=nxt, total=total)
