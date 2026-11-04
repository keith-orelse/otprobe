from fastapi import APIRouter, Depends, Query

from app import schemas
from app.api.deps import CursorQ, LimitQ, admin_only, any_user, get_ctx, operator_or_admin
from app.context import AppContext
from app.core.idempotency import Idempotency, require_idempotency
from app.core.principal import CurrentUser
from app.services import assessments, comparison, findings

router = APIRouter()


@router.post("/assets/{asset_id}/assessments", status_code=202, response_model=schemas.AssessmentRun,
             tags=["assessments"], summary="Queue a deep assessment task for the asset's agent")
async def run_assessment(asset_id: str, body: schemas.AssessmentCreate | None = None,
                         user: CurrentUser = Depends(operator_or_admin),
                         idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    policy = body.policy_id if body else None
    return idem.execute(ctx.db, 202, lambda s: assessments.request(ctx, s, asset_id, user, policy))


@router.get("/assessments", response_model=schemas.Page[schemas.AssessmentRun], tags=["assessments"])
async def list_runs(limit: int = LimitQ, cursor: str | None = CursorQ,
                    asset_id: str | None = Query(None, alias="assetId"), source: str | None = None,
                    user: CurrentUser = Depends(any_user), ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return assessments.list_runs(s, limit, cursor, asset_id, source)


@router.get("/assessments/{run_id}", response_model=schemas.AssessmentRun, tags=["assessments"],
            summary="Run with rule results, score, UNKNOWN count, evidence, drift and configuration changes")
async def get_run(run_id: str, user: CurrentUser = Depends(any_user), ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return assessments.get_run(s, run_id)


@router.get("/policies", response_model=list[schemas.PolicyInfo], tags=["assessments"],
            summary="Loaded policies and their rules (from the /rules data files)")
async def policies(user: CurrentUser = Depends(any_user), ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return assessments.list_policies(s)


@router.get("/drift-events", response_model=schemas.Page[schemas.DriftEvent], tags=["assessments"])
async def drift_events(limit: int = LimitQ, cursor: str | None = CursorQ,
                       asset_id: str | None = Query(None, alias="assetId"), user: CurrentUser = Depends(any_user),
                       ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return assessments.list_drift(s, limit, cursor, asset_id)


@router.get("/findings", response_model=schemas.Page[schemas.Finding], tags=["findings"])
async def list_findings(limit: int = LimitQ, cursor: str | None = CursorQ,
                        asset_id: str | None = Query(None, alias="assetId"),
                        status: str | None = Query(None, description="Comma-separated, e.g. OPEN,REOPENED"),
                        severity: str | None = None, rule_id: str | None = Query(None, alias="ruleId"),
                        source: str | None = None, user: CurrentUser = Depends(any_user),
                        ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return findings.list_findings(s, user, limit, cursor, asset_id, status, severity, rule_id, source)


@router.get("/findings/{finding_id}", response_model=schemas.Finding, tags=["findings"],
            summary="Finding with lifecycle events and linked drift events")
async def get_finding(finding_id: str, user: CurrentUser = Depends(any_user), ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return findings.get(s, user, finding_id)


@router.post("/findings/{finding_id}/accept-risk", response_model=schemas.Finding, tags=["findings"],
             summary="Accept risk (admin only, reason required, optional expiry)")
async def accept_risk(finding_id: str, body: schemas.AcceptRisk, user: CurrentUser = Depends(admin_only),
                      idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    return idem.execute(ctx.db, 200, lambda s: findings.accept_risk(s, finding_id, user, body.reason, body.expires_at))


@router.post("/findings/{finding_id}/revoke-acceptance", response_model=schemas.Finding, tags=["findings"])
async def revoke(finding_id: str, body: schemas.RevokeAcceptance | None = None, user: CurrentUser = Depends(admin_only),
                 idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    reason = body.reason if body else None
    return idem.execute(ctx.db, 200, lambda s: findings.revoke_acceptance(s, finding_id, user, reason))


@router.get("/assets/{asset_id}/comparison", response_model=schemas.Comparison, tags=["assets"],
            summary="Agentless vs Deep Agent comparison computed from collected data")
async def compare(asset_id: str, user: CurrentUser = Depends(any_user), ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return comparison.build(s, asset_id)


@router.post("/assets/{asset_id}/authorize", tags=["assets"], summary="Mark a rogue device as authorized (admin)")
async def authorize(asset_id: str, body: schemas.AuthorizeAsset, user: CurrentUser = Depends(admin_only),
                    idem: Idempotency = Depends(require_idempotency), ctx: AppContext = Depends(get_ctx)):
    return idem.execute(ctx.db, 200, lambda s: findings.authorize_asset(s, asset_id, user, body.reason))
