from fastapi import APIRouter, Depends

from app import schemas
from app.api.deps import admin_only, get_ctx
from app.context import AppContext
from app.core.idempotency import Idempotency, require_idempotency
from app.core.principal import CurrentUser
from app.services import demo

router = APIRouter(prefix="/demo", tags=["demo"])


@router.get("/state", response_model=schemas.DemoState, summary="SIMULATION CONTROLS: devices and active faults")
async def state(user: CurrentUser = Depends(admin_only), ctx: AppContext = Depends(get_ctx)):
    return demo.state(ctx)


@router.post("/devices/{device_id}/faults", response_model=schemas.DemoDevice,
             summary="SIMULATION CONTROLS: set or clear a fault on a simulated device (admin)")
async def fault(device_id: str, req: schemas.DemoFault, user: CurrentUser = Depends(admin_only),
                idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    action = demo.apply_fault(ctx, device_id, req, user)
    return idem.execute(ctx.db, 200, action)
