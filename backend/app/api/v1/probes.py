from fastapi import APIRouter, Depends

from app import schemas
from app.api.deps import CursorQ, LimitQ, get_actor, get_ctx
from app.context import AppContext
from app.core.audit import Actor
from app.core.idempotency import Idempotency, require_idempotency
from app.services import probes

router = APIRouter(tags=["probes"])


@router.post("/assets/{asset_id}/probes", status_code=202, response_model=schemas.ProbeRun,
             summary="Run agentless probe (ICMP -> ARP -> WinRM -> WMI / SNMP / SSH / MQTT -> collect)")
async def start(asset_id: str, idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx),
                actor: Actor = Depends(get_actor)):
    return idem.execute(ctx.db, 202, lambda s: probes.create_probe(ctx, s, asset_id, actor))


@router.get("/probes", response_model=schemas.Page[schemas.ProbeRun])
async def list_probes(limit: int = LimitQ, cursor: str | None = CursorQ, asset_id: str | None = None,
                      ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return probes.list_probes(s, limit, cursor, asset_id)


@router.get("/probes/{probe_id}", response_model=schemas.ProbeRun)
async def get_probe(probe_id: str, ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return probes.get_probe(s, probe_id)
