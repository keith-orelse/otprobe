from __future__ import annotations

from collections import Counter

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import schemas
from app.adapters.registry import AdapterRegistry
from app.core.clock import utcnow
from app.models import Agent, Approval, Asset, AuditEvent, DiscoveryJob, DriftEvent, EvidenceChange, Finding
from app.services.assessments import compliance, drift_schema
from app.services.discovery import to_schema as job_schema


def summary(ctx, session: Session, registry: AdapterRegistry) -> schemas.DashboardSummary:
    assets = list(session.scalars(select(Asset)))
    names = {a.id: a.display_name for a in assets}
    last = session.scalar(select(DiscoveryJob).order_by(DiscoveryJob.created_at.desc()).limit(1))
    recent = session.scalars(select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(12))
    open_findings = Counter(f.severity for f in session.scalars(
        select(Finding).where(Finding.status.in_(["OPEN", "REOPENED"]))))
    scores, unknown = [], 0
    monitoring = []
    for a in assets:
        c = compliance(ctx, session, a)
        if c.score is not None:
            scores.append(c.score)
            unknown += c.counts.get("unknown", 0)
        agent = session.get(Agent, a.current_agent_id) if a.current_agent_id else None
        if agent is not None and agent.status != "REMOVED":
            since = int((utcnow() - agent.last_heartbeat_at).total_seconds()) if agent.last_heartbeat_at else None
            monitoring.append(schemas.MonitoringRow(
                asset_id=a.id, asset_name=a.display_name, agent_id=agent.id, agent_status=agent.status,
                seconds_since_heartbeat=since, last_assessment_at=c.last_assessment_at,
                next_assessment_at=c.next_assessment_at, score=c.score, unknown=c.counts.get("unknown", 0),
                open_findings=c.open_findings))
    drift = session.scalars(select(DriftEvent).order_by(DriftEvent.detected_at.desc()).limit(8))
    changes = session.scalars(select(EvidenceChange).order_by(EvidenceChange.detected_at.desc()).limit(10))
    by_level_type: dict[str, dict[str, int]] = {}
    for a in assets:
        bucket = by_level_type.setdefault(a.level, {})
        key = a.device_type or "Unclassified"
        bucket[key] = bucket.get(key, 0) + 1
    agents = Counter(a.status for a in session.scalars(select(Agent)) if a.status != "REMOVED")
    pending = session.scalar(select(func.count()).select_from(Approval).where(Approval.status == "PENDING")) or 0
    return schemas.DashboardSummary(
        assets_by_level_type=by_level_type, pending_approvals=pending, agents=dict(agents),
        assets={"total": len(assets), **Counter(a.status for a in assets)},
        assets_by_level=dict(Counter(a.level for a in assets)),
        eligibility=dict(Counter(a.eligibility for a in assets)),
        rogue=sum(a.is_rogue for a in assets),
        last_discovery=job_schema(session, last, False) if last else None,
        recent_events=[schemas.AuditEvent.model_validate(e) for e in recent],
        adapters=registry.describe(),
        open_findings=dict(open_findings),
        compliance_avg=round(sum(scores) / len(scores), 1) if scores else None,
        unknown_total=unknown,
        monitoring=monitoring,
        recent_drift=[drift_schema(session, d) for d in drift],
        recent_changes=[{"assetId": c.asset_id, "assetName": names.get(c.asset_id), "path": c.path,
                         "before": c.before, "after": c.after, "detectedAt": c.detected_at.isoformat(),
                         "runId": c.run_id} for c in changes],
    )


def nav_counts(ctx, session: Session) -> schemas.NavCounts:
    count = lambda stmt: session.scalar(select(func.count()).select_from(stmt.subquery())) or 0  # noqa: E731
    open_f = select(Finding.id).where(Finding.status.in_(["OPEN", "REOPENED"]))
    return schemas.NavCounts(
        pending_approvals=count(select(Approval.id).where(Approval.status == "PENDING")),
        open_findings=count(open_f),
        critical_findings=count(open_f.where(Finding.severity.in_(["CRITICAL", "HIGH"]))),
        agents_attention=count(select(Agent.id).where(Agent.status.in_(["STALE", "OFFLINE", "ERROR"]))),
        rogue_assets=count(select(Asset.id).where(Asset.is_rogue.is_(True))),
        running_workflows=len(ctx.runner.active()),
    )
