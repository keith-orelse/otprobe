"""Cross-cutting tables: workflow steps, audit trail, idempotency keys."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.clock import utcnow
from app.core.ids import new_id
from app.models.base import Base, UtcDateTime


class WorkflowStep(Base):
    __tablename__ = "workflow_steps"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    workflow_kind: Mapped[str] = mapped_column(String(16))
    workflow_id: Mapped[str] = mapped_column(String(36), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="PENDING")
    detail: Mapped[str] = mapped_column(Text, default="")
    progress: Mapped[float | None] = mapped_column(Float)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    seq: Mapped[int] = mapped_column(Integer, unique=True)
    at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    actor_type: Mapped[str] = mapped_column(String(16))
    actor_id: Mapped[str | None] = mapped_column(String(64))
    actor_name: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64), index=True)
    entity_kind: Mapped[str] = mapped_column(String(32))
    entity_id: Mapped[str | None] = mapped_column(String(64), index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(128), index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class IdempotencyKey(Base):
    __tablename__ = "idempotency_keys"
    principal: Mapped[str] = mapped_column(String(64), primary_key=True)
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    method: Mapped[str] = mapped_column(String(8))
    path: Mapped[str] = mapped_column(String(255))
    request_hash: Mapped[str] = mapped_column(String(64))
    status_code: Mapped[int] = mapped_column(Integer)
    response: Mapped[Any] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
