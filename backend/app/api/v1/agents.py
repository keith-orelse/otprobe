from typing import Any

from fastapi import APIRouter, Body, Depends, Query
from fastapi.responses import Response

from app import schemas
from app.api.deps import CursorQ, LimitQ, admin_only, any_user, current_agent, get_ctx, operator_or_admin
from app.context import AppContext
from app.core.idempotency import Idempotency, require_idempotency
from app.core.principal import CurrentAgent, CurrentUser
from app.services import agents, assessments, removals

router = APIRouter(tags=["agents"])


@router.get("/agents", response_model=schemas.Page[schemas.Agent])
async def list_agents(limit: int = LimitQ, cursor: str | None = CursorQ, status: str | None = None,
                      user: CurrentUser = Depends(any_user), ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return agents.list_agents(ctx, s, limit, cursor, status)


@router.get("/agents/{agent_id}", response_model=schemas.Agent)
async def get_agent(agent_id: str, user: CurrentUser = Depends(any_user), ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return agents.get(ctx, s, agent_id)


@router.get("/agents/{agent_id}/heartbeats", response_model=schemas.Page[schemas.HeartbeatRecord])
async def list_heartbeats(agent_id: str, limit: int = LimitQ, cursor: str | None = CursorQ,
                          user: CurrentUser = Depends(any_user), ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return agents.heartbeats(s, agent_id, limit, cursor)


@router.post("/agents/{agent_id}/removals", status_code=201, response_model=schemas.Removal,
             summary="Request agent removal / rollback (operator/admin). Creates a PENDING approval.")
async def request_removal(agent_id: str, body: schemas.RemovalCreate | None = None,
                          user: CurrentUser = Depends(operator_or_admin),
                          idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    purpose = body.purpose if body else "Decommission POC agent"
    return idem.execute(ctx.db, 201, lambda s: removals.request(ctx, s, agent_id, user, purpose))


@router.post("/agents/{agent_id}/restart", summary="Restart the agent service via WinRM (recovery for a crash)")
async def restart(agent_id: str, user: CurrentUser = Depends(operator_or_admin), ctx: AppContext = Depends(get_ctx)):
    return await removals.restart_agent(ctx, agent_id, user)


@router.get("/removals", response_model=schemas.Page[schemas.Removal], tags=["agents"])
async def list_removals(limit: int = LimitQ, cursor: str | None = CursorQ, user: CurrentUser = Depends(any_user),
                        ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return removals.list_removals(s, user, limit, cursor)


@router.get("/removals/{removal_id}", response_model=schemas.Removal, tags=["agents"])
async def get_removal(removal_id: str, user: CurrentUser = Depends(any_user), ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return removals.get(s, user, removal_id)


@router.post("/removals/{removal_id}/start", status_code=202, response_model=schemas.Removal, tags=["agents"],
             summary="Start the approved rollback (requester or admin)")
async def start_removal(removal_id: str, user: CurrentUser = Depends(operator_or_admin),
                        idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    return idem.execute(ctx.db, 202, lambda s: removals.start(ctx, s, removal_id, user))


@router.post("/removals/{removal_id}/retry", status_code=202, response_model=schemas.Removal, tags=["agents"],
             summary="Retry a FAILED rollback under the same approval (admin)")
async def retry_removal(removal_id: str, user: CurrentUser = Depends(admin_only),
                        idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    return idem.execute(ctx.db, 202, lambda s: removals.start(ctx, s, removal_id, user, retry=True))


# ---------------------------------------------------------------- called BY agents (outbound only)
@router.post("/agents/enroll", status_code=201, response_model=schemas.EnrollResponse, tags=["agent-protocol"],
             summary="Exchange a single-use enrollment token for a per-agent credential (shown once). "
                     "The token itself makes the call idempotent: a replay is rejected as already used.")
async def enroll(req: schemas.EnrollRequest, ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        body, _ = agents.enroll(ctx, s, req)
    return body


@router.post("/agents/{agent_id}/heartbeat", status_code=204, tags=["agent-protocol"])
async def heartbeat(hb: schemas.HeartbeatIn, agent: CurrentAgent = Depends(current_agent),
                    ctx: AppContext = Depends(get_ctx)):
    agents.heartbeat(ctx, agent, hb)
    return Response(status_code=204)


@router.get("/agents/{agent_id}/tasks", tags=["agent-protocol"], summary="Long-poll for tasks")
async def tasks(wait_sec: int = Query(20, alias="waitSec", ge=0, le=30), agent: CurrentAgent = Depends(current_agent),
                ctx: AppContext = Depends(get_ctx)) -> list[dict]:
    return await assessments.poll_tasks(ctx, agent, wait_sec)


@router.post("/agents/{agent_id}/tasks/{task_id}/evidence", status_code=202, tags=["agent-protocol"],
             summary="Upload the evidence document for a task; evaluation runs server-side (docs/RULES.md §4)")
async def evidence(task_id: str, body: dict[str, Any] = Body(...), agent: CurrentAgent = Depends(current_agent),
                   ctx: AppContext = Depends(get_ctx)) -> dict[str, Any]:
    return assessments.submit_evidence(ctx, agent, task_id, body)
