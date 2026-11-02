from fastapi import APIRouter, Depends, Query

from app import schemas
from app.api.deps import CursorQ, LimitQ, any_user, get_ctx, operator_or_admin
from app.context import AppContext
from app.core.idempotency import Idempotency, require_idempotency
from app.core.principal import CurrentUser
from app.services import probes

router = APIRouter(tags=["probes"])


@router.post("/assets/{asset_id}/probes", status_code=202, response_model=schemas.ProbeRun,
             summary="Run agentless probe (ICMP -> ARP -> WinRM -> WMI / SNMP / SSH / MQTT -> collect)")
async def start(asset_id: str, user: CurrentUser = Depends(operator_or_admin),
                idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    return idem.execute(ctx.db, 202, lambda s: probes.create_probe(ctx, s, asset_id, user.actor))


@router.get("/probes", response_model=schemas.Page[schemas.ProbeRun])
async def list_probes(limit: int = LimitQ, cursor: str | None = CursorQ,
                      asset_id: str | None = Query(None, alias="assetId"),
                      user: CurrentUser = Depends(any_user), ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return probes.list_probes(s, limit, cursor, asset_id)


@router.get("/probes/{probe_id}", response_model=schemas.ProbeRun)
async def get_probe(probe_id: str, user: CurrentUser = Depends(any_user), ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return probes.get_probe(s, probe_id)
