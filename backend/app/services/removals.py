from __future__ import annotations

from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import schemas
from app.adapters.base import RemoteOperation, Target
from app.context import AppContext
from app.core import audit, events
from app.core.clock import utcnow
from app.core.correlation import get_correlation_id
from app.core.errors import ProblemError, not_found
from app.core.principal import CurrentUser
from app.engines.inventory import effective_fields
from app.engines.remote import installer_profile, platform_for, profile_port
from app.engines.removal.engine import RemovalEngine
from app.models import Agent, Approval, Asset, Removal, WorkflowStep
from app.services import approvals, safety
from app.services.common import paginate
from app.workflow.machine import AGENT, APPROVAL, REMOVAL

REMOVABLE = ("ONLINE", "STALE", "OFFLINE", "ERROR")


def _operator_ok(rem: Removal, user: CurrentUser) -> str | None:
    if user.role == "ADMIN" or (user.role == "OPERATOR" and user.username == rem.requested_by):
        return None
    return "Only the requester or an admin can run this"


def actions(rem: Removal, user: CurrentUser) -> dict[str, schemas.ActionState]:
    deny = _operator_ok(rem, user)
    start = schemas.ActionState(enabled=rem.status == "APPROVED" and deny is None,
                                reason=deny if deny and rem.status == "APPROVED" else
                                "Start the rollback" if rem.status == "APPROVED" else
                                "Awaiting approval" if rem.status == "REQUESTED" else f"Removal is {rem.status}")
    admin = user.role == "ADMIN"
    retry = schemas.ActionState(enabled=rem.status == "FAILED" and admin,
                                reason=("Retry under the same approval" if admin else "Only an admin can retry")
                                if rem.status == "FAILED" else "Only failed removals can be retried")
    return {"start": start, "retry": retry}


def remove_action(session: Session, agent: Agent | None) -> schemas.ActionState:
    if agent is None or agent.status not in REMOVABLE:
        return schemas.ActionState(enabled=False, reason=f"Agent is {agent.status if agent else 'not installed'}")
    active = session.scalar(select(Removal).where(Removal.agent_id == agent.id,
                                                  Removal.status.in_(["REQUESTED", "APPROVED", "RUNNING", "FAILED"])))
    if active is not None:
        return schemas.ActionState(enabled=False, reason=f"Removal {active.id[:8]} is {active.status}")
    return schemas.ActionState(enabled=True, reason="Request removal (requires approval)")


def restart_action(agent: Agent | None) -> schemas.ActionState:
    if agent is None or agent.status not in ("ONLINE", "STALE", "OFFLINE"):
        return schemas.ActionState(enabled=False, reason="No installed agent to restart")
    return schemas.ActionState(enabled=True, reason="Restart the agent service on the host (WinRM or SSH)")


def to_schema(session: Session, rem: Removal, user: CurrentUser, detail: bool = True) -> schemas.Removal:
    out = schemas.Removal.model_validate(rem)
    asset = session.get(Asset, rem.asset_id)
    out.asset_name = asset.display_name if asset else None
    if rem.approval_id:
        out.approval = approvals.to_schema(session, session.get(Approval, rem.approval_id), user)
    out.actions = actions(rem, user)
    if detail:
        out.steps = [schemas.WorkflowStep.model_validate(s) for s in session.scalars(
            select(WorkflowStep).where(WorkflowStep.workflow_id == rem.id).order_by(WorkflowStep.seq))]
    return out


def request(ctx: AppContext, session: Session, agent_id: str, user: CurrentUser, purpose: str
            ) -> tuple[dict[str, Any], None]:
    agent = session.get(Agent, agent_id)
    if agent is None:
        raise not_found("Agent", agent_id)
    action = remove_action(session, agent)
    if not action.enabled:
        raise ProblemError(409, "removal-not-possible", "Removal not possible", action.reason)
    asset = session.get(Asset, agent.asset_id)
    rem = Removal(asset_id=asset.id, agent_id=agent.id, purpose=purpose, requested_by=user.username,
                  correlation_id=get_correlation_id())
    REMOVAL.create(session, rem, user.actor, {"agentId": agent.id, "assetId": asset.id})
    appr = Approval(subject_kind="REMOVAL", subject_id=rem.id, target_asset_id=asset.id, requested_by=user.username,
                    purpose=purpose, criticality=asset.criticality)
    APPROVAL.create(session, appr, user.actor, {"subjectKind": "REMOVAL", "subjectId": rem.id})
    rem.approval_id = appr.id
    return to_schema(session, rem, user).dump(), None


def _load(session: Session, removal_id: str) -> Removal:
    rem = session.get(Removal, removal_id)
    if rem is None:
        raise not_found("Removal", removal_id)
    return rem


def start(ctx: AppContext, session: Session, removal_id: str, user: CurrentUser, retry: bool = False
          ) -> tuple[dict[str, Any], Callable[[], None]]:
    rem = _load(session, removal_id)
    act = actions(rem, user)["retry" if retry else "start"]
    if not act.enabled:
        raise ProblemError(403 if "Only" in act.reason else 409,
                           "forbidden" if "Only" in act.reason else "invalid-state-transition",
                           "Action not available", act.reason)
    safety.ensure_can_scan(ctx, session, [session.get(Asset, rem.asset_id).ip])
    agent = session.get(Agent, rem.agent_id)
    if agent.status != "REMOVING":
        AGENT.transition(session, agent, "REMOVING", user.actor, details={"removalId": rem.id})
    session.get(Asset, rem.asset_id).agent_state = "REMOVING"
    REMOVAL.transition(session, rem, "RUNNING", user.actor)
    rem.started_at, rem.failure_code, rem.failure_detail = utcnow(), None, None
    body = to_schema(session, rem, user).dump()
    return body, lambda: ctx.runner.submit(f"removal:{removal_id}", RemovalEngine(ctx).run(removal_id, retry))


def list_removals(session: Session, user: CurrentUser, limit: int, cursor: str | None) -> schemas.Page:
    rows, nxt, total = paginate(session, select(Removal).order_by(Removal.created_at.desc()), limit, cursor)
    return schemas.Page[schemas.Removal](items=[to_schema(session, r, user, False) for r in rows], next_cursor=nxt,
                                         total=total)


def get(session: Session, user: CurrentUser, removal_id: str) -> schemas.Removal:
    return to_schema(session, _load(session, removal_id), user)


async def restart_agent(ctx: AppContext, agent_id: str, user: CurrentUser) -> dict[str, Any]:
    with ctx.db.session() as s:
        agent = s.get(Agent, agent_id)
        if agent is None:
            raise not_found("Agent", agent_id)
        act = restart_action(agent)
        if not act.enabled:
            raise ProblemError(409, "restart-not-possible", "Restart not possible", act.reason)
        ip = s.get(Asset, agent.asset_id).ip
        safety.ensure_can_scan(ctx, s, [ip])
        fields = {p: r.value for p, r in effective_fields(s, agent.asset_id).items()}
        platform = platform_for(fields)
        profile = installer_profile(s, agent, platform)
    remote = ctx.registry.get(platform.protocol)
    cred = await ctx.vault.resolve(profile, purpose=f"restart agent {agent_id}", correlation_id=get_correlation_id())
    res, session = await remote.open_session(Target(ip, port=await profile_port(ctx, profile, platform.port),
                                                    credential=cred, options=platform.options(fields)))
    if session is None:
        raise ProblemError(502, f"{platform.access.lower()}-failed",
                           f"Could not reach the host over {platform.label}", res.error_detail)
    try:
        r = await remote.execute(session, RemoteOperation.START_SERVICE, {"name": platform.service})
    finally:
        await remote.close_session(session)
    with ctx.db.session() as s:
        audit.record(s, user.actor, "AGENT_SERVICE_RESTARTED", "agent", agent_id,
                     {"result": "ok" if r.ok else r.error_detail})
        events.stage(s, "agent.status", "agent", agent_id, {})
    if not r.ok:
        raise ProblemError(502, "restart-failed", "Service restart failed", r.error_detail)
    return {"agentId": agent_id, "service": "running",
            "message": f"{platform.service} restarted; the agent resumes heartbeats on its own"}
