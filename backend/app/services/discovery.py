from __future__ import annotations

import ipaddress
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import schemas
from app.adapters.base import Protocol
from app.adapters.registry import AdapterRegistry
from app.context import AppContext
from app.core.audit import Actor
from app.core.correlation import get_correlation_id
from app.core.errors import ProblemError, not_found
from app.engines.discovery.engine import DiscoveryEngine
from app.models import DiscoveryJob, DiscoveryObservation, WorkflowStep, Zone
from app.services import safety
from app.services.common import paginate
from app.workflow.machine import DISCOVERY


def _validate_targets(ctx: AppContext, session: Session, targets: list[str]) -> tuple[list[str], bool]:
    safety.ensure_can_scan(ctx, session, targets)   # live mode: scope, exclusions, kill switch
    zones = list(session.scalars(select(Zone)))
    normalized, safe = [], False
    for t in targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            raise ProblemError(422, "invalid-target", "Invalid discovery target",
                               f"'{t}' is not a valid CIDR") from None
        zone = next((z for z in zones if net.subnet_of(ipaddress.ip_network(z.cidr))), None)
        if zone is None:
            if ctx.settings.live:
                raise ProblemError(422, "target-out-of-scope", "Target outside the scan scope",
                                   f"{t} is not inside an approved scan scope entry")
            raise ProblemError(422, "target-not-in-simulated-network", "Target outside the simulated network",
                               f"{t} is not inside a configured zone. OTProbe never scans real networks.")
        if not zone.scannable:
            raise ProblemError(422, "zone-not-scannable", "Zone is not scannable", f"{zone.name} is never scanned")
        normalized.append(str(net))
        safe |= zone.safe_mode
    if len(set(normalized)) != len(normalized):
        raise ProblemError(422, "duplicate-target", "Duplicate discovery target")
    return normalized, safe


METHOD_INFO = {
    Protocol.ARP: "Passive ARP/neighbor tables. Finds every powered device, including ICMP-silent field devices.",
    Protocol.ICMP: "Echo sweep, rate-limited in safe mode. No reply does not mean a device is offline.",
    Protocol.TCP: "TCP connect to known service ports on hosts already seen. Handshake and close only, no payload.",
    Protocol.SNMP: "SNMPv3 GET of sysName/sysDescr/entity with the read-only profile OT-SNMPV3-RO.",
}


def default_methods(registry: AdapterRegistry) -> list[str]:
    return [p.value for p in METHOD_INFO if registry.has(p)]


def methods(registry: AdapterRegistry) -> list[schemas.DiscoveryMethod]:
    out = []
    for p, description in METHOD_INFO.items():
        if not registry.has(p):
            continue
        d = registry.get(p).descriptor()
        out.append(schemas.DiscoveryMethod(method=p.value, label=d.display_label, implementation=d.implementation,
                                           simulated=d.simulated, description=description))
    return out


def _actions(job: DiscoveryJob) -> dict[str, schemas.ActionState]:
    active = job.status in ("QUEUED", "RUNNING")
    return {"cancel": schemas.ActionState(enabled=active, reason="Cancel this job" if active
                                          else f"Job is {job.status}")}


def to_schema(session: Session, job: DiscoveryJob, with_steps: bool = True) -> schemas.DiscoveryJob:
    out = schemas.DiscoveryJob.model_validate(job)
    out.actions = _actions(job)
    if with_steps:
        steps = session.scalars(select(WorkflowStep).where(WorkflowStep.workflow_id == job.id)
                                .order_by(WorkflowStep.seq))
        out.steps = [schemas.WorkflowStep.model_validate(s) for s in steps]
    return out


def create_job(ctx: AppContext, session: Session, req: schemas.DiscoveryJobCreate, actor: Actor
               ) -> tuple[dict[str, Any], Callable[[], None]]:
    targets, safe = _validate_targets(ctx, session, req.targets)
    supported = default_methods(ctx.registry)
    chosen = list(dict.fromkeys(req.methods or supported))
    unsupported = [m for m in chosen if m not in supported]
    if unsupported:
        raise ProblemError(422, "method-not-supported", "Discovery method not available",
                           f"{', '.join(unsupported)} is not available in this mode")
    active = session.scalar(select(DiscoveryJob).where(DiscoveryJob.status.in_(["QUEUED", "RUNNING"])))
    if active is not None:
        raise ProblemError(409, "discovery-already-running", "A discovery job is already running",
                           f"Job {active.id} is {active.status}")
    job = DiscoveryJob(targets=targets, methods=chosen, safe_mode=safe, snmp_profile=req.snmp_profile,
                       requested_by=actor.name, correlation_id=get_correlation_id())
    DISCOVERY.create(session, job, actor, {"targets": targets, "methods": job.methods, "safeMode": safe,
                                           "snmpProfile": req.snmp_profile})
    body = to_schema(session, job, with_steps=False).dump()
    job_id = job.id
    return body, lambda: ctx.runner.submit(f"discovery:{job_id}", DiscoveryEngine(ctx).run(job_id))


def cancel_job(ctx: AppContext, session: Session, job_id: str, actor: Actor) -> tuple[dict[str, Any], None]:
    job = session.get(DiscoveryJob, job_id)
    if job is None:
        raise not_found("Discovery job", job_id)
    if job.status == "QUEUED":
        DISCOVERY.transition(session, job, "CANCELLED", actor, "Cancelled before start")
    elif job.status == "RUNNING" and ctx.runner.cancel(f"discovery:{job_id}"):
        pass  # engine performs RUNNING -> CANCELLED when the task is cancelled
    else:
        DISCOVERY.transition(session, job, "CANCELLED", actor)  # raises 409 for terminal states
    return to_schema(session, job).dump(), None


def list_jobs(session: Session, limit: int, cursor: str | None, status: str | None) -> schemas.Page:
    stmt = select(DiscoveryJob).order_by(DiscoveryJob.created_at.desc())
    if status:
        stmt = stmt.where(DiscoveryJob.status == status)
    rows, nxt, total = paginate(session, stmt, limit, cursor)
    return schemas.Page[schemas.DiscoveryJob](items=[to_schema(session, j, False) for j in rows],
                                              next_cursor=nxt, total=total)


def get_job(session: Session, job_id: str) -> schemas.DiscoveryJob:
    job = session.get(DiscoveryJob, job_id)
    if job is None:
        raise not_found("Discovery job", job_id)
    return to_schema(session, job)


def list_observations(session: Session, job_id: str, limit: int, cursor: str | None) -> schemas.Page:
    if session.get(DiscoveryJob, job_id) is None:
        raise not_found("Discovery job", job_id)
    stmt = (select(DiscoveryObservation).where(DiscoveryObservation.job_id == job_id)
            .order_by(DiscoveryObservation.observed_at))
    rows, nxt, total = paginate(session, stmt, limit, cursor)
    return schemas.Page[schemas.Observation](items=[schemas.Observation.model_validate(r) for r in rows],
                                             next_cursor=nxt, total=total)
