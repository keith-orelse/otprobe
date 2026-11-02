"""Agent trust: enrollment (token -> credential), heartbeats, task polling, and the heartbeat watchdog."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import schemas
from app.context import AppContext
from app.core import audit, events
from app.core.audit import Actor, system
from app.core.clock import utcnow
from app.core.crypto import sha256_hex
from app.core.errors import ProblemError, not_found
from app.core.principal import CurrentAgent
from app.core.security import opaque_token
from app.models import Agent, Asset, Deployment, EnrollmentToken, Heartbeat, WorkflowStep
from app.services.common import paginate
from app.workflow.machine import AGENT, DEPLOYMENT

log = logging.getLogger("otprobe.agents")
WATCHDOG = system("heartbeat-watchdog")
STALE_AFTER, OFFLINE_AFTER = 3, 6
TASK_POLL_WAIT_SEC = 20


def _reject(ctx: AppContext, detail: str, token_id: str | None, deployment_id: str | None, hostname: str) -> None:
    with ctx.db.session() as s:
        audit.record(s, Actor("AGENT", f"enroll:{hostname[:40]}"), "ENROLLMENT_TOKEN_REJECTED", "deployment",
                     deployment_id, {"reason": detail, "tokenId": token_id, "hostname": hostname})
    raise ProblemError(401, "enrollment-token-invalid", "Enrollment rejected", detail)


def enroll(ctx: AppContext, session: Session, req: schemas.EnrollRequest) -> tuple[dict[str, Any], None]:
    tok = session.scalar(select(EnrollmentToken).where(EnrollmentToken.token_hash == sha256_hex(req.enrollment_token)))
    if tok is None:
        _reject(ctx, "Unknown enrollment token", None, None, req.hostname)
    now = utcnow()
    for bad, why in ((tok.used_at is not None, "Enrollment token already used"),
                     (tok.revoked_at is not None, "Enrollment token revoked"),
                     (tok.expires_at < now, "Enrollment token expired")):
        if bad:
            _reject(ctx, why, tok.id, tok.deployment_id, req.hostname)
    dep = session.get(Deployment, tok.deployment_id)
    asset = session.get(Asset, tok.asset_id)
    agent = session.get(Agent, dep.agent_id) if dep.agent_id else None
    if dep.status not in ("ENROLLING", "DEPLOYING") or agent is None or agent.status != "ENROLLING":
        _reject(ctx, f"Deployment is {dep.status}; not accepting enrollment", tok.id, dep.id, req.hostname)
    if asset.hostname and req.hostname.lower() != asset.hostname.lower():
        _reject(ctx, f"Hostname {req.hostname} does not match bound asset {asset.hostname}", tok.id, dep.id,
                req.hostname)
    credential, cred_hash = opaque_token("agt")
    tok.used_at = now
    agent.credential_hash, agent.credential_prefix = cred_hash, credential[:8]
    agent.host_fingerprint, agent.enrolled_at, agent.version = req.host_fingerprint, now, req.agent_version
    audit.record(session, Actor("AGENT", f"agent:{agent.id[:8]}", agent.id), "AGENT_CREDENTIAL_ISSUED", "agent",
                 agent.id, {"deploymentId": dep.id, "tokenId": tok.id, "credentialPrefix": agent.credential_prefix,
                            "hostname": req.hostname})
    body = schemas.EnrollResponse(agent_id=agent.id, agent_credential=credential,
                                  heartbeat_interval_sec=ctx.settings.heartbeat_interval_sec,
                                  task_poll_wait_sec=TASK_POLL_WAIT_SEC).dump()
    # The plaintext credential is returned exactly once; the idempotency record must not keep it.
    return body, None


def heartbeat(ctx: AppContext, agent_ref: CurrentAgent, hb: schemas.HeartbeatIn) -> None:
    now = utcnow()
    with ctx.db.session() as s:
        agent = s.get(Agent, agent_ref.id)
        if agent.status in ("REMOVING", "REMOVED"):
            raise ProblemError(409, "agent-removed", "Agent is being removed", f"Agent is {agent.status}")
        s.add(Heartbeat(agent_id=agent.id, seq=hb.seq, received_at=now, agent_time=hb.agent_time,
                        payload=hb.model_dump(mode="json", by_alias=True, exclude={"seq", "agent_time"})))
        agent.last_heartbeat_at, agent.last_heartbeat_seq, agent.missed_heartbeats = now, hb.seq, 0
        asset = s.get(Asset, agent.asset_id)
        if agent.status == "ENROLLING":
            AGENT.transition(s, agent, "ONLINE", agent_ref.actor, "First heartbeat after enrollment")
            dep = s.get(Deployment, agent.deployment_id)
            if dep.status == "ENROLLING":
                dep.finished_at = now
                DEPLOYMENT.transition(s, dep, "COMPLETED", agent_ref.actor, details={"agentId": agent.id})
                step = s.scalar(select(WorkflowStep).where(WorkflowStep.workflow_id == dep.id,
                                                           WorkflowStep.name == "AWAIT_ENROLLMENT"))
                if step is not None:
                    step.status, step.finished_at = "OK", now
                    step.detail = f"Agent {agent.id[:8]} enrolled (credential {agent.credential_prefix}…) and is ONLINE"
                    events.stage(s, "deployment.step", "deployment", dep.id,
                                 {"name": step.name, "seq": step.seq, "status": step.status, "detail": step.detail})
        elif agent.status in ("STALE", "OFFLINE"):
            AGENT.transition(s, agent, "ONLINE", agent_ref.actor, "Heartbeat received",
                             {"lastSeq": hb.seq})
        asset.agent_state = agent.status
        events.stage(s, "agent.heartbeat", "agent", agent.id, {"seq": hb.seq, "status": agent.status,
                                                               "at": now.isoformat()})


async def poll_tasks(ctx: AppContext, agent_ref: CurrentAgent, wait_sec: int) -> list[dict[str, Any]]:
    """Long-poll. Assessment tasks are introduced in Phase 4; until then the poll simply times out empty."""
    await asyncio.sleep(min(wait_sec, TASK_POLL_WAIT_SEC))
    return []


# ---------------------------------------------------------------- console
def to_schema(ctx: AppContext, session: Session, a: Agent) -> schemas.Agent:
    out = schemas.Agent.model_validate(a)
    asset = session.get(Asset, a.asset_id)
    out.asset_name = asset.display_name if asset else None
    out.heartbeat_interval_sec = ctx.settings.heartbeat_interval_sec
    if a.last_heartbeat_at:
        out.seconds_since_heartbeat = int((utcnow() - a.last_heartbeat_at).total_seconds())
    return out


def list_agents(ctx: AppContext, session: Session, limit: int, cursor: str | None, status: str | None) -> schemas.Page:
    stmt = select(Agent).order_by(Agent.installed_at.desc())
    if status:
        stmt = stmt.where(Agent.status == status)
    rows, nxt, total = paginate(session, stmt, limit, cursor)
    return schemas.Page[schemas.Agent](items=[to_schema(ctx, session, a) for a in rows], next_cursor=nxt, total=total)


def get(ctx: AppContext, session: Session, agent_id: str) -> schemas.Agent:
    a = session.get(Agent, agent_id)
    if a is None:
        raise not_found("Agent", agent_id)
    return to_schema(ctx, session, a)


def heartbeats(session: Session, agent_id: str, limit: int, cursor: str | None) -> schemas.Page:
    if session.get(Agent, agent_id) is None:
        raise not_found("Agent", agent_id)
    stmt = select(Heartbeat).where(Heartbeat.agent_id == agent_id).order_by(Heartbeat.received_at.desc())
    rows, nxt, total = paginate(session, stmt, limit, cursor)
    return schemas.Page[schemas.HeartbeatRecord](items=[schemas.HeartbeatRecord.model_validate(h) for h in rows],
                                                 next_cursor=nxt, total=total)


# ---------------------------------------------------------------- watchdog
def watchdog_tick(ctx: AppContext) -> None:
    interval = ctx.settings.heartbeat_interval_sec
    now = utcnow()
    with ctx.db.session() as s:
        for agent in s.scalars(select(Agent).where(Agent.status.in_(["ONLINE", "STALE"]))):
            if agent.last_heartbeat_at is None:
                continue
            missed = int((now - agent.last_heartbeat_at).total_seconds() // interval)
            agent.missed_heartbeats = missed
            target = "OFFLINE" if missed >= OFFLINE_AFTER else "STALE" if missed >= STALE_AFTER else None
            if target and target != agent.status:
                if agent.status == "ONLINE" and target == "OFFLINE":
                    AGENT.transition(s, agent, "STALE", WATCHDOG, f"{missed} heartbeats missed")
                AGENT.transition(s, agent, target, WATCHDOG, f"{missed} heartbeats missed",
                                 {"lastHeartbeatAt": agent.last_heartbeat_at.isoformat()})
                s.get(Asset, agent.asset_id).agent_state = agent.status
                events.stage(s, "asset.updated", "asset", agent.asset_id, {"agentState": agent.status})
        timeout = ctx.settings.enrollment_timeout_sec
        for dep in s.scalars(select(Deployment).where(Deployment.status == "ENROLLING")):
            if dep.enrolling_since and (now - dep.enrolling_since).total_seconds() > timeout:
                detail = f"No successful enrollment within {int(timeout)} s"
                dep.failure_code, dep.failure_detail, dep.finished_at = "ENROLLMENT_FAILED", detail, now
                DEPLOYMENT.transition(s, dep, "FAILED", WATCHDOG, detail, {"failureCode": "ENROLLMENT_FAILED"})
                for tok in s.scalars(select(EnrollmentToken).where(EnrollmentToken.deployment_id == dep.id,
                                                                   EnrollmentToken.used_at.is_(None))):
                    tok.revoked_at = now
                agent = s.get(Agent, dep.agent_id) if dep.agent_id else None
                if agent is not None and agent.status == "ENROLLING":
                    AGENT.transition(s, agent, "ERROR", WATCHDOG, detail)
                    s.get(Asset, agent.asset_id).agent_state = "ERROR"
                step = s.scalar(select(WorkflowStep).where(WorkflowStep.workflow_id == dep.id,
                                                           WorkflowStep.name == "AWAIT_ENROLLMENT"))
                if step is not None:
                    step.status, step.detail, step.finished_at = "FAILED", detail, now


async def run_watchdog(ctx: AppContext) -> None:
    period = max(0.1, min(1.0, ctx.settings.heartbeat_interval_sec / 4))
    while True:
        try:
            watchdog_tick(ctx)
        except Exception:  # noqa: BLE001 - the watchdog must keep running
            log.exception("watchdog tick failed")
        await asyncio.sleep(period)
