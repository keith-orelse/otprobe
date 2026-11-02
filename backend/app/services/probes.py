from __future__ import annotations

from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import schemas
from app.context import AppContext
from app.core.audit import Actor
from app.core.correlation import get_correlation_id
from app.core.errors import ProblemError, not_found
from app.engines.probing.engine import ProbeEngine
from app.models import Asset, ProbeResult, ProbeRun, WorkflowStep
from app.services.common import paginate
from app.workflow.machine import PROBE


def to_schema(session: Session, run: ProbeRun, detail: bool = True) -> schemas.ProbeRun:
    out = schemas.ProbeRun.model_validate(run)
    asset = session.get(Asset, run.asset_id)
    out.asset_name = asset.display_name if asset else None
    if detail:
        out.steps = [schemas.WorkflowStep.model_validate(s) for s in session.scalars(
            select(WorkflowStep).where(WorkflowStep.workflow_id == run.id).order_by(WorkflowStep.seq))]
        out.results = [schemas.ProbeResult.model_validate(r) for r in session.scalars(
            select(ProbeResult).where(ProbeResult.probe_run_id == run.id).order_by(ProbeResult.collected_at))]
    return out


def create_probe(ctx: AppContext, session: Session, asset_id: str, actor: Actor
                 ) -> tuple[dict[str, Any], Callable[[], None]]:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise not_found("Asset", asset_id)
    active = session.scalar(select(ProbeRun).where(ProbeRun.asset_id == asset_id,
                                                   ProbeRun.status.in_(["QUEUED", "RUNNING"])))
    if active is not None:
        raise ProblemError(409, "probe-already-running", "A probe is already running for this asset",
                           f"Probe {active.id} is {active.status}")
    run = ProbeRun(asset_id=asset_id, requested_by=actor.name, correlation_id=get_correlation_id())
    PROBE.create(session, run, actor, {"assetId": asset_id, "ip": asset.ip})
    body = to_schema(session, run, detail=False).dump()
    run_id = run.id
    return body, lambda: ctx.runner.submit(f"probe:{run_id}", ProbeEngine(ctx).run(run_id))


def list_probes(session: Session, limit: int, cursor: str | None, asset_id: str | None) -> schemas.Page:
    stmt = select(ProbeRun).order_by(ProbeRun.created_at.desc())
    if asset_id:
        stmt = stmt.where(ProbeRun.asset_id == asset_id)
    rows, nxt, total = paginate(session, stmt, limit, cursor)
    return schemas.Page[schemas.ProbeRun](items=[to_schema(session, r, False) for r in rows], next_cursor=nxt,
                                          total=total)


def get_probe(session: Session, probe_id: str) -> schemas.ProbeRun:
    run = session.get(ProbeRun, probe_id)
    if run is None:
        raise not_found("Probe run", probe_id)
    return to_schema(session, run)
