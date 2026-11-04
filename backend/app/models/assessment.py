"""Phase 4: policies, agent tasks, assessment runs, rule results, findings, drift, configuration changes."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.clock import utcnow
from app.core.ids import new_id
from app.models.base import Base, UtcDateTime


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("key", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    key: Mapped[str] = mapped_column(String(64), index=True)     # e.g. windows-engineering-baseline
    version: Mapped[str] = mapped_column(String(16))
    name: Mapped[str] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(16))
    digest: Mapped[str] = mapped_column(String(64))
    document: Mapped[dict[str, Any]] = mapped_column(JSON)
    source_file: Mapped[str] = mapped_column(String(128))
    loaded_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class AgentTask(Base):
    __tablename__ = "agent_tasks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), index=True)
    assessment_run_id: Mapped[str | None] = mapped_column(String(36))
    correlation_id: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    dispatched_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    deadline_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    completed_at: Mapped[datetime | None] = mapped_column(UtcDateTime)


class AssessmentRun(Base):
    __tablename__ = "assessment_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    agent_id: Mapped[str | None] = mapped_column(String(36))
    policy_key: Mapped[str] = mapped_column(String(64))
    policy_version: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(16))     # DEEP_AGENT | AGENTLESS
    trigger: Mapped[str] = mapped_column(String(16))    # MANUAL | SCHEDULED | PROBE
    status: Mapped[str] = mapped_column(String(16), index=True)
    requested_by: Mapped[str] = mapped_column(String(64))
    evidence: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    score: Mapped[float | None] = mapped_column(Float)
    counts: Mapped[dict[str, int]] = mapped_column(JSON, default=dict)
    previous_run_id: Mapped[str | None] = mapped_column(String(36))
    error: Mapped[str | None] = mapped_column(Text)
    correlation_id: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime)


class RuleResult(Base):
    __tablename__ = "rule_results"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("assessment_runs.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    rule_id: Mapped[str] = mapped_column(String(32))
    rule_version: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(8))
    severity: Mapped[str] = mapped_column(String(16))
    evidence_path: Mapped[str] = mapped_column(String(128))
    observed: Mapped[Any] = mapped_column(JSON)
    expected: Mapped[str] = mapped_column(Text)
    message: Mapped[str | None] = mapped_column(Text)
    previous_status: Mapped[str | None] = mapped_column(String(8))
    references: Mapped[list[str]] = mapped_column(JSON, default=list)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("asset_id", "rule_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)
    result_status: Mapped[str] = mapped_column(String(8))   # FAIL | WARNING that raised it
    source: Mapped[str] = mapped_column(String(16))
    observed: Mapped[Any] = mapped_column(JSON)
    expected: Mapped[str] = mapped_column(Text)
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    remediation: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    reopen_count: Mapped[int] = mapped_column(Integer, default=0)
    accepted_by: Mapped[str | None] = mapped_column(String(64))
    accepted_reason: Mapped[str | None] = mapped_column(Text)
    accepted_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    accepted_until: Mapped[datetime | None] = mapped_column(UtcDateTime)
    last_run_id: Mapped[str | None] = mapped_column(String(36))


class FindingEvent(Base):
    __tablename__ = "finding_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    from_status: Mapped[str | None] = mapped_column(String(16))
    to_status: Mapped[str] = mapped_column(String(16))
    run_id: Mapped[str | None] = mapped_column(String(36))
    actor: Mapped[str] = mapped_column(String(64))
    reason: Mapped[str | None] = mapped_column(Text)
    at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class DriftEvent(Base):
    __tablename__ = "drift_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("assessment_runs.id"), index=True)
    previous_run_id: Mapped[str] = mapped_column(String(36))
    rule_id: Mapped[str] = mapped_column(String(32))
    from_status: Mapped[str] = mapped_column(String(8))
    to_status: Mapped[str] = mapped_column(String(8))
    evidence_path: Mapped[str] = mapped_column(String(128))
    before: Mapped[Any] = mapped_column(JSON)
    after: Mapped[Any] = mapped_column(JSON)
    finding_id: Mapped[str | None] = mapped_column(String(36))
    detected_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class EvidenceChange(Base):
    __tablename__ = "evidence_changes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("assessment_runs.id"), index=True)
    previous_run_id: Mapped[str] = mapped_column(String(36))
    path: Mapped[str] = mapped_column(String(128))
    before: Mapped[Any] = mapped_column(JSON)
    after: Mapped[Any] = mapped_column(JSON)
    detected_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
