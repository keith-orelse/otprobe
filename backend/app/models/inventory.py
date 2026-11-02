from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, Boolean, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.clock import utcnow
from app.core.ids import new_id
from app.models.base import Base, UtcDateTime


class Zone(Base):
    __tablename__ = "zones"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    cidr: Mapped[str] = mapped_column(String(64), unique=True)
    default_level: Mapped[str] = mapped_column(String(8))
    safe_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    scannable: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str] = mapped_column(Text, default="")


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    mac: Mapped[str | None] = mapped_column(String(17), unique=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    ip_num: Mapped[int] = mapped_column(BigInteger, index=True, default=0)
    display_name: Mapped[str] = mapped_column(String(255))
    hostname: Mapped[str | None] = mapped_column(String(255))
    sys_name: Mapped[str | None] = mapped_column(String(255))
    device_type: Mapped[str | None] = mapped_column(String(128))
    os_name: Mapped[str | None] = mapped_column(String(255))
    level: Mapped[str] = mapped_column(String(8))
    criticality: Mapped[str | None] = mapped_column(String(16))
    criticality_source: Mapped[str] = mapped_column(String(16), default="DERIVED")
    status: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    is_rogue: Mapped[bool] = mapped_column(Boolean, default=False)
    authorized: Mapped[bool] = mapped_column(Boolean, default=True)
    agent_state: Mapped[str] = mapped_column(String(16), default="NOT_INSTALLED")
    eligibility: Mapped[str] = mapped_column(String(32), default="UNKNOWN")
    eligibility_reason: Mapped[str] = mapped_column(Text, default="Run an agentless probe to determine eligibility.")
    classification: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    discovered_by: Mapped[list[str]] = mapped_column(JSON, default=list)
    zone_id: Mapped[str | None] = mapped_column(ForeignKey("zones.id"))
    current_agent_id: Mapped[str | None] = mapped_column(String(36))
    first_seen: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    last_probe_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    version: Mapped[int] = mapped_column(Integer, default=1)

    @validates("ip")
    def _sync_ip_num(self, _key: str, value: str) -> str:
        self.ip_num = int(ipaddress.ip_address(value))
        return value


class AssetField(Base):
    __tablename__ = "asset_fields"
    __table_args__ = (UniqueConstraint("asset_id", "field_path", "source"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    field_path: Mapped[str] = mapped_column(String(128))
    value: Mapped[Any] = mapped_column(JSON)
    source: Mapped[str] = mapped_column(String(16))
    stage: Mapped[str] = mapped_column(String(16))
    collected_at: Mapped[datetime] = mapped_column(UtcDateTime)
    run_kind: Mapped[str] = mapped_column(String(16))
    run_id: Mapped[str] = mapped_column(String(36))


class AssetRelationship(Base):
    __tablename__ = "asset_relationships"
    __table_args__ = (UniqueConstraint("src_asset_id", "dst_asset_id", "kind", "protocol", "port"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    src_asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    dst_asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    kind: Mapped[str] = mapped_column(String(8))  # LINK (physical, switch FDB/LLDP) | FLOW (communication)
    protocol: Mapped[str] = mapped_column(String(32))
    port: Mapped[int | None] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(16))
    first_seen: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class DiscoveryJob(Base):
    __tablename__ = "discovery_jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    targets: Mapped[list[str]] = mapped_column(JSON)
    methods: Mapped[list[str]] = mapped_column(JSON)
    safe_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(16), index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    phase: Mapped[str | None] = mapped_column(String(32))
    devices_found: Mapped[int] = mapped_column(Integer, default=0)
    new_assets: Mapped[int] = mapped_column(Integer, default=0)
    rogue_count: Mapped[int] = mapped_column(Integer, default=0)
    requested_by: Mapped[str] = mapped_column(String(64))
    error: Mapped[str | None] = mapped_column(Text)
    correlation_id: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime)


class DiscoveryObservation(Base):
    __tablename__ = "discovery_observations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    job_id: Mapped[str] = mapped_column(ForeignKey("discovery_jobs.id"), index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), index=True)
    ip: Mapped[str] = mapped_column(String(45))
    mac: Mapped[str | None] = mapped_column(String(17))
    method: Mapped[str] = mapped_column(String(16))
    responded: Mapped[bool] = mapped_column(Boolean, default=True)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    observed_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class ProbeRun(Base):
    __tablename__ = "probe_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)
    requested_by: Mapped[str] = mapped_column(String(64))
    classification: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    eligibility: Mapped[str | None] = mapped_column(String(32))
    eligibility_reason: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    correlation_id: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime)


class ProbeResult(Base):
    __tablename__ = "probe_results"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    probe_run_id: Mapped[str] = mapped_column(ForeignKey("probe_runs.id"), index=True)
    protocol: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16))
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    stages: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    latency_ms: Mapped[float | None] = mapped_column(Float)
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_detail: Mapped[str | None] = mapped_column(Text)
    collected_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class CredentialProfile(Base):
    __tablename__ = "credential_profiles"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    protocol: Mapped[str] = mapped_column(String(16))
    username: Mapped[str] = mapped_column(String(128))
    secret_ciphertext: Mapped[str] = mapped_column(Text)
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    rotated_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
