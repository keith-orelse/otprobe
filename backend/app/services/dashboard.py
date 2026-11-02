from __future__ import annotations

from collections import Counter

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import schemas
from app.adapters.registry import AdapterRegistry
from app.models import Asset, AuditEvent, DiscoveryJob
from app.services.discovery import to_schema as job_schema


def summary(session: Session, registry: AdapterRegistry) -> schemas.DashboardSummary:
    assets = list(session.scalars(select(Asset)))
    last = session.scalar(select(DiscoveryJob).order_by(DiscoveryJob.created_at.desc()).limit(1))
    recent = session.scalars(select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(12))
    return schemas.DashboardSummary(
        assets={"total": len(assets), **Counter(a.status for a in assets)},
        assets_by_level=dict(Counter(a.level for a in assets)),
        eligibility=dict(Counter(a.eligibility for a in assets)),
        rogue=sum(a.is_rogue for a in assets),
        last_discovery=job_schema(session, last, False) if last else None,
        recent_events=[schemas.AuditEvent.model_validate(e) for e in recent],
        adapters=registry.describe(),
    )
