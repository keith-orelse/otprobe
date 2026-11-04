from fastapi import APIRouter, Depends

from app import schemas
from app.api.deps import admin_only, any_user, get_ctx, operator_or_admin
from app.context import AppContext
from app.core.idempotency import Idempotency, require_idempotency
from app.core.principal import CurrentUser
from app.services import safety

router = APIRouter(tags=["safety"])


@router.get("/environment", response_model=schemas.Environment,
            summary="Environment banner (public: shown on the login page too)")
async def environment(ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return safety.environment(ctx, s)


@router.get("/scope", response_model=list[schemas.ScanScope], summary="Scan scope entries")
async def list_scope(include_disabled: bool = False, user: CurrentUser = Depends(any_user),
                     ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return safety.list_scope(s, include_disabled)


@router.post("/scope", status_code=201, response_model=schemas.ScanScope,
             summary="Add a scan scope entry (admin). Nothing outside the scope is ever sent a packet")
async def create_scope(req: schemas.ScanScopeCreate, user: CurrentUser = Depends(admin_only),
                       idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    return idem.execute(ctx.db, 201, lambda s: safety.create_scope(ctx, s, req, user.actor))


@router.patch("/scope/{entry_id}", response_model=schemas.ScanScope, summary="Change a scan scope entry (admin)")
async def update_scope(entry_id: str, req: schemas.ScanScopeUpdate, user: CurrentUser = Depends(admin_only),
                       idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    return idem.execute(ctx.db, 200, lambda s: safety.update_scope(ctx, s, entry_id, req, user.actor))


@router.delete("/scope/{entry_id}", response_model=schemas.ScanScope, summary="Remove a scan scope entry (admin)")
async def delete_scope(entry_id: str, user: CurrentUser = Depends(admin_only),
                       idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    return idem.execute(ctx.db, 200, lambda s: safety.delete_scope(ctx, s, entry_id, user.actor))


@router.get("/safety", response_model=schemas.SafetyView, summary="Kill switch, safe mode and scope summary")
async def get_safety(user: CurrentUser = Depends(any_user), ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return safety.view(ctx, s)


@router.post("/safety/stop", response_model=schemas.SafetyView,
             summary="KILL SWITCH: stop all network activity and cancel running workflows (operator or admin)")
async def stop(req: schemas.SafetyReason, user: CurrentUser = Depends(operator_or_admin),
               idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    return idem.execute(ctx.db, 200, lambda s: safety.stop(ctx, s, req, user.actor))


@router.post("/safety/rearm", response_model=schemas.SafetyView, summary="Re-arm after a stop (admin)")
async def rearm(req: schemas.SafetyReason, user: CurrentUser = Depends(admin_only),
                idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    return idem.execute(ctx.db, 200, lambda s: safety.rearm(ctx, s, req, user.actor))


@router.post("/safety/safe-mode", response_model=schemas.SafetyView, summary="Turn safe mode on or off (admin)")
async def safe_mode(req: schemas.SafeModeChange, user: CurrentUser = Depends(admin_only),
                    idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    return idem.execute(ctx.db, 200, lambda s: safety.set_safe_mode(ctx, s, req, user.actor))
