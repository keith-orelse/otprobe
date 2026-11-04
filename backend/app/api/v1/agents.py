from typing import Any

from fastapi import APIRouter, Body, Depends, Query
from fastapi.responses import Response

from app import schemas
from app.api.deps import CursorQ, LimitQ, any_user, current_agent, get_ctx
from app.context import AppContext
from app.core.principal import CurrentAgent, CurrentUser
from app.services import agents, assessments

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
