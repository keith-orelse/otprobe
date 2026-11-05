"""Phase 3: users, packages, approvals, deployments, enrollment and agents."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.clock import utcnow
from app.core.ids import new_id
from app.models.base import Base, UtcDateTime


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    display_name: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(16))  # OPERATOR | APPROVER | ADMIN
    password_hash: Mapped[str] = mapped_column(String(128))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class Package(Base):
    __tablename__ = "packages"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    version: Mapped[str] = mapped_column(String(32))
    architecture: Mapped[str] = mapped_column(String(16))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    supported_os: Mapped[list[str]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16))  # ACTIVE | DEPRECATED | BLOCKED
    release_notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    subject_kind: Mapped[str] = mapped_column(String(16))  # DEPLOYMENT | REMOVAL
    subject_id: Mapped[str] = mapped_column(String(36), index=True)
    target_asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    requested_by: Mapped[str] = mapped_column(String(64))
    purpose: Mapped[str] = mapped_column(Text)
    criticality: Mapped[str | None] = mapped_column(String(16))
    maint_window_start: Mapped[datetime | None] = mapped_column(UtcDateTime)
    maint_window_end: Mapped[datetime | None] = mapped_column(UtcDateTime)
    status: Mapped[str] = mapped_column(String(16), index=True)  # PENDING | APPROVED | REJECTED | EXPIRED
    decided_by: Mapped[str | None] = mapped_column(String(64))
    decided_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class Deployment(Base):
    __tablename__ = "deployments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    package_id: Mapped[str] = mapped_column(ForeignKey("packages.id"))
    credential_profile: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24), index=True)
    purpose: Mapped[str] = mapped_column(Text)
    requested_by: Mapped[str] = mapped_column(String(64))
    approval_id: Mapped[str | None] = mapped_column(String(36))
    precheck_run_no: Mapped[int] = mapped_column(Integer, default=0)
    precheck_passed_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    agent_id: Mapped[str | None] = mapped_column(String(36))
    failure_code: Mapped[str | None] = mapped_column(String(64))
    failure_detail: Mapped[str | None] = mapped_column(Text)
    retry_of_id: Mapped[str | None] = mapped_column(String(36))
    correlation_id: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    deploy_started_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    enrolling_since: Mapped[datetime | None] = mapped_column(UtcDateTime)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime)


class PrecheckResult(Base):
    __tablename__ = "precheck_results"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    deployment_id: Mapped[str] = mapped_column(ForeignKey("deployments.id"), index=True)
    run_no: Mapped[int] = mapped_column(Integer)
    seq: Mapped[int] = mapped_column(Integer)
    check: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(8))  # PASS | FAIL | WARN
    detail: Mapped[str] = mapped_column(Text)
    checked_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    deployment_id: Mapped[str] = mapped_column(ForeignKey("deployments.id"), index=True)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime)
    used_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    deployment_id: Mapped[str] = mapped_column(ForeignKey("deployments.id"))
    status: Mapped[str] = mapped_column(String(16), index=True)
    version: Mapped[str] = mapped_column(String(32))
    credential_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    credential_prefix: Mapped[str | None] = mapped_column(String(16))
    host_fingerprint: Mapped[str | None] = mapped_column(String(128))
    platform: Mapped[str | None] = mapped_column(String(48))   # "windows/amd64 modern", reported at enrollment
    profile: Mapped[str | None] = mapped_column(String(48))    # windows-workstation, linux-host, ...
    installed_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    enrolled_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    last_heartbeat_seq: Mapped[int | None] = mapped_column(Integer)
    missed_heartbeats: Mapped[int] = mapped_column(Integer, default=0)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    removed_at: Mapped[datetime | None] = mapped_column(UtcDateTime)


class Heartbeat(Base):
    __tablename__ = "heartbeats"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    received_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    agent_time: Mapped[datetime | None] = mapped_column(UtcDateTime)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    latency_ms: Mapped[float | None] = mapped_column(Float)
