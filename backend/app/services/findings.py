from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import schemas
from app.context import AppContext
from app.core import audit
from app.core.audit import system
from app.core.clock import utcnow
from app.core.errors import ProblemError, not_found
from app.core.principal import CurrentUser
from app.engines.assessment.findings import transition
from app.models import Asset, DriftEvent, Finding, FindingEvent
from app.services.common import paginate

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def actions(f: Finding, user: CurrentUser) -> dict[str, schemas.ActionState]:
    admin = user.role == "ADMIN"
    accept = (schemas.ActionState(enabled=False, reason="Only an admin can accept risk") if not admin else
              schemas.ActionState(enabled=f.status in ("OPEN", "REOPENED"),
                                  reason="Accept risk with a reason" if f.status in ("OPEN", "REOPENED")
                                  else f"Finding is {f.status}"))
    revoke = (schemas.ActionState(enabled=False, reason="Only an admin can revoke an acceptance") if not admin else
              schemas.ActionState(enabled=f.status == "ACCEPTED_RISK",
                                  reason="Revoke the risk acceptance" if f.status == "ACCEPTED_RISK"
                                  else "Risk not accepted"))
    return {"acceptRisk": accept, "revokeAcceptance": revoke}


def to_schema(session: Session, f: Finding, user: CurrentUser, detail: bool = False) -> schemas.Finding:
    out = schemas.Finding.model_validate(f)
    asset = session.get(Asset, f.asset_id)
    out.asset_name = asset.display_name if asset else None
    out.asset_ip = asset.ip if asset else None
    out.actions = actions(f, user)
    if detail:
        out.events = [schemas.FindingEventOut.model_validate(e) for e in session.scalars(
            select(FindingEvent).where(FindingEvent.finding_id == f.id).order_by(FindingEvent.at))]
        out.drift_events = [schemas.DriftEvent.model_validate(d) for d in session.scalars(
            select(DriftEvent).where(DriftEvent.finding_id == f.id).order_by(DriftEvent.detected_at))]
    return out


def list_findings(session: Session, user: CurrentUser, limit: int, cursor: str | None, asset_id: str | None,
                  status: str | None, severity: str | None, rule_id: str | None, source: str | None) -> schemas.Page:
    stmt = select(Finding)
    for col, val in ((Finding.asset_id, asset_id), (Finding.severity, severity), (Finding.rule_id, rule_id),
                     (Finding.source, source)):
        if val:
            stmt = stmt.where(col == val)
    if status:
        stmt = stmt.where(Finding.status.in_(status.split(",")))
    rows, nxt, total = paginate(session, stmt.order_by(Finding.last_seen.desc()), limit, cursor)
    return schemas.Page[schemas.Finding](items=[to_schema(session, f, user) for f in rows], next_cursor=nxt,
                                         total=total)


def get(session: Session, user: CurrentUser, finding_id: str) -> schemas.Finding:
    f = session.get(Finding, finding_id)
    if f is None:
        raise not_found("Finding", finding_id)
    return to_schema(session, f, user, detail=True)


def accept_risk(session: Session, finding_id: str, user: CurrentUser, reason: str, expires_at: datetime | None
                ) -> tuple[dict[str, Any], None]:
    f = session.get(Finding, finding_id)
    if f is None:
        raise not_found("Finding", finding_id)
    if user.role != "ADMIN":
        raise ProblemError(403, "forbidden", "Insufficient role", "Only an admin can accept risk")
    if not reason or len(reason.strip()) < 5:
        raise ProblemError(422, "reason-required", "A reason (at least 5 characters) is required to accept risk")
    if expires_at is not None and expires_at <= utcnow():
        raise ProblemError(422, "invalid-expiry", "Risk acceptance expiry must be in the future")
    f.accepted_by, f.accepted_reason, f.accepted_at, f.accepted_until = user.username, reason, utcnow(), expires_at
    transition(session, f, "ACCEPTED_RISK", user.actor, reason=reason,
               details={"expiresAt": expires_at.isoformat() if expires_at else None})
    return to_schema(session, f, user, detail=True).dump(), None


def revoke_acceptance(session: Session, finding_id: str, user: CurrentUser, reason: str | None
                      ) -> tuple[dict[str, Any], None]:
    f = session.get(Finding, finding_id)
    if f is None:
        raise not_found("Finding", finding_id)
    if user.role != "ADMIN":
        raise ProblemError(403, "forbidden", "Insufficient role", "Only an admin can revoke a risk acceptance")
    transition(session, f, "OPEN", user.actor, reason=reason or "Acceptance revoked")
    f.accepted_until = None
    return to_schema(session, f, user, detail=True).dump(), None


def expiry_tick(ctx: AppContext) -> None:
    now = utcnow()
    with ctx.db.session() as s:
        for f in s.scalars(select(Finding).where(Finding.status == "ACCEPTED_RISK", Finding.accepted_until < now)):
            transition(s, f, "OPEN", system("risk-expiry"), reason="Risk acceptance expired")


def authorize_asset(session: Session, asset_id: str, user: CurrentUser, reason: str) -> tuple[dict[str, Any], None]:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise not_found("Asset", asset_id)
    if user.role != "ADMIN":
        raise ProblemError(403, "forbidden", "Insufficient role", "Only an admin can authorize a device")
    if not asset.is_rogue:
        raise ProblemError(409, "not-rogue", "Asset is not flagged as rogue")
    asset.is_rogue, asset.authorized = False, True
    audit.record(session, user.actor, "ASSET_AUTHORIZED", "asset", asset.id, {"reason": reason, "mac": asset.mac})
    f = session.scalar(select(Finding).where(Finding.asset_id == asset.id, Finding.rule_id == "NET-ROGUE-001"))
    if f is not None and f.status in ("OPEN", "REOPENED", "ACCEPTED_RISK"):
        f.resolved_at = utcnow()
        transition(session, f, "RESOLVED", user.actor, reason=f"Device authorized: {reason}")
    return {"assetId": asset.id, "authorized": True}, None
