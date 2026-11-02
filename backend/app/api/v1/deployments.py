from fastapi import APIRouter, Depends, Query

from app import schemas
from app.api.deps import CursorQ, LimitQ, any_user, approver_or_admin, get_ctx, operator_or_admin
from app.context import AppContext
from app.core.idempotency import Idempotency, require_idempotency
from app.core.principal import CurrentUser
from app.services import approvals, deployments

router = APIRouter(tags=["deployments"])


@router.post("/deployments", status_code=201, response_model=schemas.Deployment,
             summary="Request agent deployment (operator/admin). Creates a PENDING approval.")
async def create(req: schemas.DeploymentCreate, user: CurrentUser = Depends(operator_or_admin),
                 idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    return idem.execute(ctx.db, 201, lambda s: deployments.create(ctx, s, req, user))


@router.get("/deployments", response_model=schemas.Page[schemas.Deployment])
async def list_deployments(limit: int = LimitQ, cursor: str | None = CursorQ, status: str | None = None,
                           asset_id: str | None = Query(None, alias="assetId"), user: CurrentUser = Depends(any_user),
                           ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return deployments.list_deployments(ctx, s, user, limit, cursor, status, asset_id)


@router.get("/deployments/{deployment_id}", response_model=schemas.Deployment)
async def get(deployment_id: str, user: CurrentUser = Depends(any_user), ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return deployments.get(ctx, s, user, deployment_id)


@router.post("/deployments/{deployment_id}/precheck", status_code=202, response_model=schemas.Deployment,
             summary="Run precheck (requester or admin). From APPROVED, PRECHECK_FAILED or PRECHECK_PASSED.")
async def precheck(deployment_id: str, user: CurrentUser = Depends(operator_or_admin),
                   idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    return idem.execute(ctx.db, 202, lambda s: deployments.start_precheck(ctx, s, deployment_id, user))


@router.post("/deployments/{deployment_id}/deploy", status_code=202, response_model=schemas.Deployment,
             summary="Deploy (requester or admin). Only from PRECHECK_PASSED, inside the maintenance window.")
async def deploy(deployment_id: str, user: CurrentUser = Depends(operator_or_admin),
                 idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    return idem.execute(ctx.db, 202, lambda s: deployments.start_deploy(ctx, s, deployment_id, user))


@router.post("/deployments/{deployment_id}/retry", status_code=201, response_model=schemas.Deployment,
             summary="Create a new deployment request from a FAILED one (needs a new approval)")
async def retry(deployment_id: str, user: CurrentUser = Depends(operator_or_admin),
                idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    return idem.execute(ctx.db, 201, lambda s: deployments.retry(ctx, s, deployment_id, user))


@router.get("/approvals", response_model=schemas.Page[schemas.Approval], tags=["approvals"])
async def list_approvals(limit: int = LimitQ, cursor: str | None = CursorQ, status: str | None = None,
                         user: CurrentUser = Depends(any_user), ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return approvals.list_approvals(s, user, limit, cursor, status)


@router.get("/approvals/{approval_id}", response_model=schemas.Approval, tags=["approvals"])
async def get_approval(approval_id: str, user: CurrentUser = Depends(any_user), ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return approvals.get(s, user, approval_id)


@router.post("/approvals/{approval_id}/approve", response_model=schemas.Approval, tags=["approvals"],
             summary="Approve (approver/admin; never your own request)")
async def approve(approval_id: str, body: schemas.Decision | None = None,
                  user: CurrentUser = Depends(approver_or_admin), idem: Idempotency = Depends(require_idempotency),
                  ctx: AppContext = Depends(get_ctx)):
    reason = body.reason if body else None
    return idem.execute(ctx.db, 200, lambda s: approvals.decide(ctx, s, approval_id, user, True, reason))


@router.post("/approvals/{approval_id}/reject", response_model=schemas.Approval, tags=["approvals"],
             summary="Reject (approver/admin; reason required)")
async def reject(approval_id: str, body: schemas.Decision, user: CurrentUser = Depends(approver_or_admin),
                 idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    return idem.execute(ctx.db, 200, lambda s: approvals.decide(ctx, s, approval_id, user, False, body.reason))


@router.get("/packages", response_model=list[schemas.Package], tags=["packages"])
async def packages(user: CurrentUser = Depends(any_user), ctx: AppContext = Depends(get_ctx)):
    from sqlalchemy import select

    from app.models import Package
    with ctx.db.session() as s:
        return [schemas.Package.model_validate(p) for p in s.scalars(select(Package).order_by(Package.version))]
