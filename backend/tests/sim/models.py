"""Simulated world tables. Read/written ONLY by app.sim and tests.sim.adapters."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.core.clock import utcnow
from app.core.ids import new_id
from app.models.base import UtcDateTime


class SimBase(DeclarativeBase):
    pass


class SimDevice(SimBase):
    __tablename__ = "sim_devices"
    device_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), unique=True)
    mac: Mapped[str] = mapped_column(String(17), unique=True)
    hostname: Mapped[str] = mapped_column(String(255))
    vendor: Mapped[str] = mapped_column(String(255))
    model: Mapped[str] = mapped_column(String(255))
    device_type: Mapped[str] = mapped_column(String(64))
    level: Mapped[str] = mapped_column(String(8))
    powered: Mapped[bool] = mapped_column(Boolean, default=True)
    state: Mapped[dict[str, Any]] = mapped_column(JSON)


class SimFault(SimBase):
    __tablename__ = "sim_faults"
    __table_args__ = (UniqueConstraint("device_id", "fault"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    device_id: Mapped[str] = mapped_column(String(64))  # "*" = global
    fault: Mapped[str] = mapped_column(String(64))
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    set_by: Mapped[str] = mapped_column(String(64))
    set_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class SimMqttClient(SimBase):
    __tablename__ = "sim_mqtt_clients"
    client_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    device_id: Mapped[str] = mapped_column(String(64))
    source_ip: Mapped[str] = mapped_column(String(45))
    connected: Mapped[bool] = mapped_column(Boolean, default=True)
    topics: Mapped[list[str]] = mapped_column(JSON, default=list)


class SimMeta(SimBase):
    __tablename__ = "sim_meta"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON)
