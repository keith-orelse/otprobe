from fastapi import APIRouter, Depends

from app import schemas
from app.api.deps import CursorQ, LimitQ, get_actor, get_ctx
from app.context import AppContext
from app.core.audit import Actor
from app.core.idempotency import Idempotency, require_idempotency
from app.services import discovery

router = APIRouter(prefix="/discovery", tags=["discovery"])


@router.post("/jobs", status_code=202, response_model=schemas.DiscoveryJob,
             summary="Start a discovery job (targets must be inside a configured simulated zone)")
async def start(req: schemas.DiscoveryJobCreate, idem: Idempotency = Depends(require_idempotency),
                ctx: AppContext = Depends(get_ctx), actor: Actor = Depends(get_actor)):
    return idem.execute(ctx.db, 202, lambda s: discovery.create_job(ctx, s, req, actor))


@router.get("/methods", response_model=list[schemas.DiscoveryMethod], summary="Discovery methods and their adapters")
async def list_methods(ctx: AppContext = Depends(get_ctx)):
    return discovery.methods(ctx.registry)


@router.get("/jobs", response_model=schemas.Page[schemas.DiscoveryJob])
async def list_jobs(limit: int = LimitQ, cursor: str | None = CursorQ, status: str | None = None,
                    ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return discovery.list_jobs(s, limit, cursor, status)


@router.get("/jobs/{job_id}", response_model=schemas.DiscoveryJob)
async def get_job(job_id: str, ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return discovery.get_job(s, job_id)


@router.post("/jobs/{job_id}/cancel", response_model=schemas.DiscoveryJob)
async def cancel(job_id: str, idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx),
                 actor: Actor = Depends(get_actor)):
    return idem.execute(ctx.db, 200, lambda s: discovery.cancel_job(ctx, s, job_id, actor))


@router.get("/jobs/{job_id}/observations", response_model=schemas.Page[schemas.Observation])
async def observations(job_id: str, limit: int = LimitQ, cursor: str | None = CursorQ,
                       ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return discovery.list_observations(s, job_id, limit, cursor)
