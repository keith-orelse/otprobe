from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import schemas
from app.context import AppContext
from app.core import audit
from app.core.clock import utcnow
from app.core.errors import ProblemError, not_found
from app.core.principal import CurrentUser
from app.models import Approval, Asset, Deployment
from app.services.common import paginate
from app.workflow.machine import APPROVAL, DEPLOYMENT

DECIDERS = ("APPROVER", "ADMIN")


def actions(a: Approval, user: CurrentUser) -> dict[str, schemas.ActionState]:
    if a.status != "PENDING":
        state = schemas.ActionState(enabled=False, reason=f"Already {a.status.lower()}")
    elif user.role not in DECIDERS:
        state = schemas.ActionState(enabled=False, reason="Only an approver or admin can decide")
    elif user.username == a.requested_by:
        state = schemas.ActionState(enabled=False, reason="You requested this; another approver must decide")
    else:
        state = schemas.ActionState(enabled=True, reason="Pending your decision")
    return {"approve": state, "reject": state}


def to_schema(session: Session, a: Approval, user: CurrentUser) -> schemas.Approval:
    out = schemas.Approval.model_validate(a)
    asset = session.get(Asset, a.target_asset_id)
    out.target_name = asset.display_name if asset else None
    if a.maint_window_start and a.maint_window_end:
        out.maintenance_window = schemas.MaintenanceWindow(start=a.maint_window_start, end=a.maint_window_end)
    out.actions = actions(a, user)
    return out


def list_approvals(session: Session, user: CurrentUser, limit: int, cursor: str | None, status: str | None
                   ) -> schemas.Page:
    stmt = select(Approval).order_by(Approval.created_at.desc())
    if status:
        stmt = stmt.where(Approval.status == status)
    rows, nxt, total = paginate(session, stmt, limit, cursor)
    return schemas.Page[schemas.Approval](items=[to_schema(session, a, user) for a in rows], next_cursor=nxt,
                                          total=total)


def get(session: Session, user: CurrentUser, approval_id: str) -> schemas.Approval:
    a = session.get(Approval, approval_id)
    if a is None:
        raise not_found("Approval", approval_id)
    return to_schema(session, a, user)


def decide(ctx: AppContext, session: Session, approval_id: str, user: CurrentUser, approve: bool, reason: str | None
           ) -> tuple[dict[str, Any], None]:
    a = session.get(Approval, approval_id)
    if a is None:
        raise not_found("Approval", approval_id)
    if user.username == a.requested_by:
        # Persist the denial even though the request fails.
        with ctx.db.session() as s2:
            audit.record(s2, user.actor, "APPROVAL_SELF_DENIED", "approval", a.id,
                         {"subjectId": a.subject_id, "requestedBy": a.requested_by})
        raise ProblemError(403, "self-approval-forbidden", "Requester cannot approve their own request",
                           f"{user.username} requested {a.subject_kind.lower()} {a.subject_id}; "
                           "a different approver must decide")
    if user.role not in DECIDERS:
        raise ProblemError(403, "forbidden", "Insufficient role", "Requires role APPROVER or ADMIN")
    if a.status != "PENDING":
        raise ProblemError(409, "invalid-state-transition", "Invalid state transition",
                           f"Approval {a.id} cannot go from {a.status} to {'APPROVED' if approve else 'REJECTED'}")
    if not approve and not reason:
        raise ProblemError(422, "reason-required", "A reason is required to reject")
    if approve and a.criticality == "CRITICAL" and not reason:
        raise ProblemError(422, "reason-required", "A reason is required to approve a deployment to a critical asset")
    dep = session.get(Deployment, a.subject_id) if a.subject_kind == "DEPLOYMENT" else None
    now = utcnow()
    if approve and a.maint_window_end and a.maint_window_end < now:
        APPROVAL.transition(session, a, "EXPIRED", user.actor, "Maintenance window ended before a decision")
        if dep is not None:
            DEPLOYMENT.transition(session, dep, "REJECTED", user.actor, "Approval expired")
        return to_schema(session, a, user).dump(), None
    a.decided_by, a.decided_at, a.reason = user.username, now, reason
    APPROVAL.transition(session, a, "APPROVED" if approve else "REJECTED", user.actor, reason,
                        {"subjectId": a.subject_id})
    if dep is not None:
        DEPLOYMENT.transition(session, dep, "APPROVED" if approve else "REJECTED", user.actor, reason,
                              {"approvalId": a.id})
    return to_schema(session, a, user).dump(), None
