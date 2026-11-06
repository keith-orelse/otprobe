"""Demo Controls API (/api/v1/demo, admin only). Mounted only by the test simulator."""

from fastapi import APIRouter, Depends

from app.api.deps import admin_only, get_ctx
from app.context import AppContext
from app.core.idempotency import Idempotency, require_idempotency
from app.core.principal import CurrentUser
from tests.sim import demo, schemas
from tests.sim.reset import reset as do_reset

router = APIRouter(prefix="/api/v1/demo", tags=["demo"])


@router.get("/state", response_model=schemas.DemoState, summary="SIMULATION CONTROLS: devices and active faults")
async def state(user: CurrentUser = Depends(admin_only), ctx: AppContext = Depends(get_ctx)):
    return demo.state(ctx)


@router.post("/devices/{device_id}/faults", response_model=schemas.DemoDevice,
             summary="SIMULATION CONTROLS: set or clear a fault on a simulated device (admin)")
async def fault(device_id: str, req: schemas.DemoFault, user: CurrentUser = Depends(admin_only),
                idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    action = demo.apply_fault(ctx, device_id, req, user)
    return idem.execute(ctx.db, 200, action)


@router.post("/rogue", summary="SIMULATION CONTROLS: inject a rogue device into the simulated network (admin)")
async def rogue(user: CurrentUser = Depends(admin_only), idem: Idempotency = Depends(require_idempotency),
                ctx: AppContext = Depends(get_ctx)):
    return idem.execute(ctx.db, 201, demo.inject_rogue(ctx, user))


@router.post("/reset", response_model=schemas.DemoResetResult,
             summary="SIMULATION CONTROLS: Reset POC to seed state (typed confirmation; audit log is kept)")
async def reset(req: schemas.DemoReset, user: CurrentUser = Depends(admin_only), ctx: AppContext = Depends(get_ctx)):
    return await do_reset(ctx, req, user)


@router.post("/devices/{device_id}/config", response_model=schemas.DemoDevice,
             summary="SIMULATION CONTROLS: change host configuration (firewall, antivirus, software, patches)")
async def config(device_id: str, req: schemas.DemoConfig, user: CurrentUser = Depends(admin_only),
                 idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    action = demo.apply_config(ctx, device_id, req, user)
    return idem.execute(ctx.db, 200, action)
