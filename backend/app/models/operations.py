"""Phase 5: agent removal (rollback) and MQTT telemetry."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.clock import utcnow
from app.core.ids import new_id
from app.models.base import Base, UtcDateTime


class Removal(Base):
    __tablename__ = "removals"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)
    purpose: Mapped[str] = mapped_column(Text)
    requested_by: Mapped[str] = mapped_column(String(64))
    approval_id: Mapped[str | None] = mapped_column(String(36))
    failure_code: Mapped[str | None] = mapped_column(String(64))
    failure_detail: Mapped[str | None] = mapped_column(Text)
    correlation_id: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime)


class TelemetryMessage(Base):
    __tablename__ = "telemetry_messages"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    topic: Mapped[str] = mapped_column(String(255), index=True)
    client_id: Mapped[str] = mapped_column(String(64))
    asset_id: Mapped[str | None] = mapped_column(String(36), index=True)
    payload: Mapped[Any] = mapped_column(JSON)
    received_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)


class MqttAccount(Base):
    """A device account on the bundled broker (Mode A). The broker allows it to publish under ``topic_prefix`` only,
    so every message on those topics is attributed to ``asset_id``. Only the Mosquitto hash of the password is kept."""
    __tablename__ = "mqtt_accounts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    topic_prefix: Mapped[str] = mapped_column(String(200), unique=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    password_changed_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
