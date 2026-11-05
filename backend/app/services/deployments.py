from __future__ import annotations

from datetime import timedelta
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import schemas
from app.context import AppContext
from app.core import events
from app.core.clock import utcnow
from app.core.correlation import get_correlation_id
from app.core.errors import ProblemError, not_found
from app.core.principal import CurrentUser
from app.engines.deployment.engine import DeploymentEngine
from app.models import Agent, Approval, Asset, Deployment, Package, PrecheckResult, WorkflowStep
from app.services import approvals, safety
from app.services.common import paginate
from app.workflow.machine import APPROVAL, DEPLOYMENT

ACTIVE = ("REQUESTED", "PENDING_APPROVAL", "APPROVED", "PRECHECK_RUNNING", "PRECHECK_PASSED", "PRECHECK_FAILED",
          "DEPLOYING", "ENROLLING")
LIVE_AGENT = ("ENROLLING", "ONLINE", "STALE", "OFFLINE", "REMOVING", "ERROR")


def _can_operate(dep: Deployment, user: CurrentUser) -> str | None:
    if user.role == "ADMIN" or (user.role == "OPERATOR" and user.username == dep.requested_by):
        return None
    return "Only the requester or an admin can run this"


def actions(ctx: AppContext, dep: Deployment, user: CurrentUser) -> dict[str, schemas.ActionState]:
    deny = _can_operate(dep, user)

    def state(allowed: bool, reason_ok: str, reason_no: str) -> schemas.ActionState:
        if allowed and deny:
            return schemas.ActionState(enabled=False, reason=deny)
        return schemas.ActionState(enabled=allowed, reason=reason_ok if allowed else reason_no)

    pre = dep.status in ("APPROVED", "PRECHECK_FAILED", "PRECHECK_PASSED")
    fresh = dep.precheck_passed_at is not None and (
        utcnow() - dep.precheck_passed_at).total_seconds() <= ctx.settings.precheck_valid_sec
    deploy_ok = dep.status == "PRECHECK_PASSED" and fresh
    if dep.status == "PRECHECK_PASSED" and not fresh:
        deploy_no = "Precheck is older than 30 minutes; run it again"
    elif dep.status in ("PENDING_APPROVAL", "REQUESTED"):
        deploy_no = "Awaiting approval"
    elif dep.status in ("APPROVED", "PRECHECK_FAILED", "PRECHECK_RUNNING"):
        deploy_no = "Precheck must pass first"
    else:
        deploy_no = f"Deployment is {dep.status}"
    return {
        "precheck": state(pre, "Run precheck", "Precheck runs after approval"
                          if dep.status in ("REQUESTED", "PENDING_APPROVAL") else f"Deployment is {dep.status}"),
        "deploy": state(deploy_ok, "Precheck passed: ready to deploy", deploy_no),
        "retry": state(dep.status == "FAILED", "Create a new request from this one (needs approval)",
                       "Only failed deployments can be retried"),
    }


def to_schema(ctx: AppContext, session: Session, dep: Deployment, user: CurrentUser, detail: bool = True
              ) -> schemas.Deployment:
    out = schemas.Deployment.model_validate(dep)
    asset = session.get(Asset, dep.asset_id)
    out.asset_name = asset.display_name if asset else None
    out.package = schemas.Package.model_validate(session.get(Package, dep.package_id))
    if dep.approval_id:
        out.approval = approvals.to_schema(session, session.get(Approval, dep.approval_id), user)
    out.actions = actions(ctx, dep, user)
    if detail:
        out.precheck = [schemas.PrecheckResult.model_validate(r) for r in session.scalars(
            select(PrecheckResult).where(PrecheckResult.deployment_id == dep.id,
                                         PrecheckResult.run_no == dep.precheck_run_no).order_by(PrecheckResult.seq))]
        out.steps = [schemas.WorkflowStep.model_validate(s) for s in session.scalars(
            select(WorkflowStep).where(WorkflowStep.workflow_id == dep.id).order_by(WorkflowStep.seq))]
    return out


def deploy_action_for_asset(session: Session, asset: Asset) -> schemas.ActionState:
    if asset.eligibility not in ("ELIGIBLE", "REVIEW_REQUIRED"):
        return schemas.ActionState(enabled=False, reason=asset.eligibility_reason)
    active = session.scalar(select(Deployment).where(Deployment.asset_id == asset.id, Deployment.status.in_(ACTIVE)))
    if active is not None:
        return schemas.ActionState(enabled=False, reason=f"Deployment {active.id[:8]} is {active.status}")
    if asset.agent_state in LIVE_AGENT:
        return schemas.ActionState(enabled=False, reason=f"Agent already present ({asset.agent_state})")
    if asset.eligibility == "REVIEW_REQUIRED":
        return schemas.ActionState(enabled=True, reason="Review required: approver review and a maintenance window")
    return schemas.ActionState(enabled=True, reason="Eligible: request deployment (requires approval)")


def create(ctx: AppContext, session: Session, req: schemas.DeploymentCreate, user: CurrentUser,
           retry_of: str | None = None) -> tuple[dict[str, Any], None]:
    asset = session.get(Asset, req.asset_id)
    if asset is None:
        raise not_found("Asset", req.asset_id)
    action = deploy_action_for_asset(session, asset)
    if not action.enabled:
        not_eligible = asset.eligibility not in ("ELIGIBLE", "REVIEW_REQUIRED")
        slug = "asset-not-eligible" if not_eligible else "deployment-conflict"
        raise ProblemError(422 if slug == "asset-not-eligible" else 409, slug,
                           "Asset not eligible for agent deployment" if slug == "asset-not-eligible"
                           else "Deployment not possible", action.reason)
    package = session.get(Package, req.package_id)
    if package is None or package.status != "ACTIVE":
        raise ProblemError(422, "package-not-active", "Package not deployable",
                           f"Package {req.package_id} is {package.status if package else 'unknown'}")
    window = req.maintenance_window
    if asset.eligibility == "REVIEW_REQUIRED" and window is None:
        raise ProblemError(422, "maintenance-window-required", "Maintenance window required",
                           "Critical assets need a maintenance window for agent deployment")
    if window and window.end <= window.start:
        raise ProblemError(422, "invalid-maintenance-window", "Maintenance window end must be after start")
    if window and window.end <= utcnow():
        raise ProblemError(422, "invalid-maintenance-window", "Maintenance window is in the past")
    dep = Deployment(asset_id=asset.id, package_id=package.id, credential_profile=req.credential_profile,
                     purpose=req.purpose, requested_by=user.username, correlation_id=get_correlation_id(),
                     retry_of_id=retry_of)
    DEPLOYMENT.create(session, dep, user.actor, {"assetId": asset.id, "ip": asset.ip, "package": package.id,
                                                  **({"retryOf": retry_of} if retry_of else {})})
    appr = Approval(subject_kind="DEPLOYMENT", subject_id=dep.id, target_asset_id=asset.id,
                    requested_by=user.username, purpose=req.purpose, criticality=asset.criticality,
                    maint_window_start=window.start if window else None,
                    maint_window_end=window.end if window else None)
    APPROVAL.create(session, appr, user.actor, {"subjectKind": "DEPLOYMENT", "subjectId": dep.id})
    dep.approval_id = appr.id
    DEPLOYMENT.transition(session, dep, "PENDING_APPROVAL", user.actor, details={"approvalId": appr.id})
    events.stage(session, "asset.updated", "asset", asset.id, {})
    return to_schema(ctx, session, dep, user).dump(), None


def _load(session: Session, dep_id: str) -> Deployment:
    dep = session.get(Deployment, dep_id)
    if dep is None:
        raise not_found("Deployment", dep_id)
    return dep


def _require(ctx: AppContext, dep: Deployment, user: CurrentUser, action: str) -> None:
    deny = _can_operate(dep, user)
    if deny:
        raise ProblemError(403, "forbidden", "Not allowed", deny)
    st = actions(ctx, dep, user)[action]
    if not st.enabled:
        raise ProblemError(409, "invalid-state-transition", "Action not available", st.reason)


def start_precheck(ctx: AppContext, session: Session, dep_id: str, user: CurrentUser
                   ) -> tuple[dict[str, Any], Callable[[], None]]:
    dep = _load(session, dep_id)
    _require(ctx, dep, user, "precheck")
    safety.ensure_can_scan(ctx, session, [session.get(Asset, dep.asset_id).ip])
    dep.precheck_run_no += 1
    dep.precheck_passed_at = None
    DEPLOYMENT.transition(session, dep, "PRECHECK_RUNNING", user.actor, details={"runNo": dep.precheck_run_no})
    body = to_schema(ctx, session, dep, user).dump()
    return body, lambda: ctx.runner.submit(f"precheck:{dep_id}", DeploymentEngine(ctx).precheck(dep_id))


def start_deploy(ctx: AppContext, session: Session, dep_id: str, user: CurrentUser
                 ) -> tuple[dict[str, Any], Callable[[], None]]:
    dep = _load(session, dep_id)
    _require(ctx, dep, user, "deploy")
    safety.ensure_can_scan(ctx, session, [session.get(Asset, dep.asset_id).ip])
    appr = session.get(Approval, dep.approval_id)
    now = utcnow()
    if appr.maint_window_start and not (appr.maint_window_start <= now <= appr.maint_window_end):
        raise ProblemError(409, "outside-maintenance-window", "Outside the approved maintenance window",
                           f"Window {appr.maint_window_start.isoformat()} – {appr.maint_window_end.isoformat()}")
    dep.deploy_started_at = now
    DEPLOYMENT.transition(session, dep, "DEPLOYING", user.actor)
    body = to_schema(ctx, session, dep, user).dump()
    return body, lambda: ctx.runner.submit(f"deploy:{dep_id}", DeploymentEngine(ctx).deploy(dep_id))


def retry(ctx: AppContext, session: Session, dep_id: str, user: CurrentUser) -> tuple[dict[str, Any], None]:
    dep = _load(session, dep_id)
    _require(ctx, dep, user, "retry")
    appr = session.get(Approval, dep.approval_id)
    window = None
    if appr.maint_window_end and appr.maint_window_end > utcnow():
        window = schemas.MaintenanceWindow(start=appr.maint_window_start, end=appr.maint_window_end)
    req = schemas.DeploymentCreate(asset_id=dep.asset_id, package_id=dep.package_id,
                                   credential_profile=dep.credential_profile, purpose=dep.purpose,
                                   maintenance_window=window)
    return create(ctx, session, req, user, retry_of=dep.id)


def list_deployments(ctx: AppContext, session: Session, user: CurrentUser, limit: int, cursor: str | None,
                     status: str | None, asset_id: str | None) -> schemas.Page:
    stmt = select(Deployment).order_by(Deployment.created_at.desc())
    if status:
        stmt = stmt.where(Deployment.status == status)
    if asset_id:
        stmt = stmt.where(Deployment.asset_id == asset_id)
    rows, nxt, total = paginate(session, stmt, limit, cursor)
    return schemas.Page[schemas.Deployment](items=[to_schema(ctx, session, d, user, False) for d in rows],
                                            next_cursor=nxt, total=total)


def get(ctx: AppContext, session: Session, user: CurrentUser, dep_id: str) -> schemas.Deployment:
    return to_schema(ctx, session, _load(session, dep_id), user)


def default_window() -> schemas.MaintenanceWindow:
    now = utcnow()
    return schemas.MaintenanceWindow(start=now, end=now + timedelta(hours=2))


def latest_agent(session: Session, asset_id: str) -> Agent | None:
    return session.scalar(select(Agent).where(Agent.asset_id == asset_id).order_by(Agent.installed_at.desc()).limit(1))
