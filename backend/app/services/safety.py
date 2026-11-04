"""Scan scope, kill switch and safe mode (docs/SAFETY_AND_SCOPE.md).

The DB is the source of truth; after every change the state is pushed into the network gate (``ctx.gate``), which
enforces it on each packet. Services that start network work call ``ensure_can_scan`` first, so an out-of-scope
request fails with a clear 409/422 instead of silently sending nothing."""

from __future__ import annotations

import ipaddress
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import schemas
from app.context import AppContext
from app.core import audit, events
from app.core.audit import Actor
from app.core.clock import utcnow
from app.core.errors import ProblemError, not_found
from app.models import SafetyState, ScanScope, Zone

MAX_PREFIX = {4: 16, 6: 112}   # INCLUDE entries may not be wider than this
SIM_BANNER = "SIMULATED ENVIRONMENT - NO REAL DEVICES ARE BEING SCANNED"


# ---- state ---------------------------------------------------------------------------------------------------------

def state_row(ctx: AppContext, session: Session) -> SafetyState:
    row = session.get(SafetyState, "global")
    if row is None:
        row = SafetyState(id="global", armed=True, safe_mode=ctx.settings.safe_mode, reason="Initial state")
        session.add(row)
        session.flush()
    return row


def active_scope(session: Session) -> list[ScanScope]:
    return list(session.scalars(select(ScanScope).where(ScanScope.disabled_at.is_(None))
                                .order_by(ScanScope.kind, ScanScope.cidr)))


def push_to_gate(ctx: AppContext, session: Session) -> None:
    if ctx.gate is None:
        return
    st = state_row(ctx, session)
    ctx.gate.load([{"id": e.id, "cidr": e.cidr, "kind": e.kind, "profile": e.profile, "plugins": e.plugins}
                   for e in active_scope(session)], armed=st.armed, safe_mode=st.safe_mode)


def reload(ctx: AppContext) -> None:
    with ctx.db.session() as s:
        push_to_gate(ctx, s)


# ---- scope ---------------------------------------------------------------------------------------------------------

def _network(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        raise ProblemError(422, "invalid-cidr", "Invalid network", f"'{cidr}' is not a valid IP network") from None


def list_scope(session: Session, include_disabled: bool = False) -> list[schemas.ScanScope]:
    stmt = select(ScanScope).order_by(ScanScope.kind, ScanScope.cidr)
    if not include_disabled:
        stmt = stmt.where(ScanScope.disabled_at.is_(None))
    return [schemas.ScanScope.model_validate(r) for r in session.scalars(stmt)]


def create_scope(ctx: AppContext, session: Session, req: schemas.ScanScopeCreate, actor: Actor
                 ) -> tuple[dict[str, Any], Callable[[], None]]:
    net = _network(req.cidr)
    if req.kind == "INCLUDE" and net.prefixlen < MAX_PREFIX[net.version]:
        raise ProblemError(422, "scope-too-wide", "Scope entry too wide",
                           f"{net} is wider than /{MAX_PREFIX[net.version]}. Add smaller ranges instead.")
    if any(e.cidr == str(net) and e.kind == req.kind for e in active_scope(session)):
        raise ProblemError(409, "scope-duplicate", "Scope entry exists", f"{req.kind} {net} is already configured")
    entry = ScanScope(cidr=str(net), kind=req.kind, profile=req.profile, level=req.level, label=req.label,
                      authorization=req.authorization, plugins=req.plugins, created_by=actor.name)
    session.add(entry)
    session.flush()
    if req.kind == "INCLUDE":
        zone = session.scalar(select(Zone).where(Zone.cidr == str(net)))
        if zone is None:
            zone = Zone(id=f"scope-{entry.id}", name=req.label or str(net), cidr=str(net), default_level=req.level,
                        description="Created from the scan scope")
            session.add(zone)
        zone.scannable, zone.safe_mode = True, req.profile == "OT_SENSITIVE"
        zone.name, zone.default_level = req.label or str(net), req.level
        entry.zone_id = zone.id
    audit.record(session, actor, "SCOPE_CHANGED", "scan_scope", entry.id,
                 {"change": "created", "after": schemas.ScanScope.model_validate(entry).dump()})
    events.stage(session, "safety.updated", "safety", "global", {"scope": "changed"})
    return schemas.ScanScope.model_validate(entry).dump(), lambda: reload(ctx)


def update_scope(ctx: AppContext, session: Session, entry_id: str, req: schemas.ScanScopeUpdate, actor: Actor
                 ) -> tuple[dict[str, Any], Callable[[], None]]:
    entry = session.get(ScanScope, entry_id)
    if entry is None or entry.disabled_at is not None:
        raise not_found("Scope entry", entry_id)
    before = schemas.ScanScope.model_validate(entry).dump()
    for name in ("profile", "level", "label", "authorization", "plugins"):
        value = getattr(req, name)
        if value is not None:
            setattr(entry, name, value)
    zone = session.get(Zone, entry.zone_id) if entry.zone_id else None
    if zone is not None:
        zone.safe_mode, zone.default_level = entry.profile == "OT_SENSITIVE", entry.level
        zone.name = entry.label or entry.cidr
    after = schemas.ScanScope.model_validate(entry).dump()
    audit.record(session, actor, "SCOPE_CHANGED", "scan_scope", entry.id,
                 {"change": "updated", "before": before, "after": after})
    events.stage(session, "safety.updated", "safety", "global", {"scope": "changed"})
    return after, lambda: reload(ctx)


def delete_scope(ctx: AppContext, session: Session, entry_id: str, actor: Actor
                 ) -> tuple[dict[str, Any], Callable[[], None]]:
    entry = session.get(ScanScope, entry_id)
    if entry is None or entry.disabled_at is not None:
        raise not_found("Scope entry", entry_id)
    entry.disabled_at = utcnow()
    zone = session.get(Zone, entry.zone_id) if entry.zone_id else None
    if zone is not None:
        zone.scannable = False
    out = schemas.ScanScope.model_validate(entry).dump()
    audit.record(session, actor, "SCOPE_CHANGED", "scan_scope", entry.id, {"change": "removed", "before": out})
    events.stage(session, "safety.updated", "safety", "global", {"scope": "changed"})
    return out, lambda: reload(ctx)


# ---- kill switch / safe mode ---------------------------------------------------------------------------------------

def view(ctx: AppContext, session: Session) -> schemas.SafetyView:
    st = state_row(ctx, session)
    scope = active_scope(session)
    return schemas.SafetyView(live=ctx.settings.live, armed=st.armed, safe_mode=st.safe_mode, changed_by=st.changed_by,
                              changed_at=st.changed_at, reason=st.reason,
                              scope_configured=any(e.kind == "INCLUDE" for e in scope),
                              includes=[e.cidr for e in scope if e.kind == "INCLUDE"],
                              excludes=[e.cidr for e in scope if e.kind == "EXCLUDE"],
                              running_workflows=ctx.runner.active(),
                              traffic=ctx.gate.totals.as_dict() if ctx.gate is not None else None)


def _changed(st: SafetyState, actor: Actor, reason: str) -> None:
    st.changed_by, st.changed_at, st.reason = actor.name, utcnow(), reason


def stop(ctx: AppContext, session: Session, req: schemas.SafetyReason, actor: Actor
         ) -> tuple[dict[str, Any], Callable[[], None]]:
    st = state_row(ctx, session)
    running = ctx.runner.active()
    st.armed = False
    _changed(st, actor, req.reason)
    audit.record(session, actor, "KILL_SWITCH_ENGAGED", "safety", "global",
                 {"reason": req.reason, "stoppedWorkflows": running})
    events.stage(session, "safety.updated", "safety", "global", {"armed": False})
    if ctx.gate is not None:
        ctx.gate.close()            # immediately, before the commit: nothing new leaves from here on

    def after() -> None:
        for key in running:
            ctx.runner.cancel(key)

    return view(ctx, session).dump(), after


def rearm(ctx: AppContext, session: Session, req: schemas.SafetyReason, actor: Actor
          ) -> tuple[dict[str, Any], Callable[[], None]]:
    st = state_row(ctx, session)
    if st.armed:
        raise ProblemError(409, "already-armed", "Already armed", "The kill switch is not engaged")
    st.armed = True
    _changed(st, actor, req.reason)
    audit.record(session, actor, "SAFETY_REARMED", "safety", "global", {"reason": req.reason})
    events.stage(session, "safety.updated", "safety", "global", {"armed": True})
    return view(ctx, session).dump(), lambda: reload(ctx)


def set_safe_mode(ctx: AppContext, session: Session, req: schemas.SafeModeChange, actor: Actor
                  ) -> tuple[dict[str, Any], Callable[[], None]]:
    st = state_row(ctx, session)
    if st.safe_mode == req.enabled:
        raise ProblemError(409, "safe-mode-unchanged", "No change",
                           f"Safe mode is already {'on' if req.enabled else 'off'}")
    st.safe_mode = req.enabled
    _changed(st, actor, req.reason)
    audit.record(session, actor, "SAFE_MODE_ENABLED" if req.enabled else "SAFE_MODE_DISABLED", "safety", "global",
                 {"reason": req.reason})
    events.stage(session, "safety.updated", "safety", "global", {"safeMode": req.enabled})
    return view(ctx, session).dump(), lambda: reload(ctx)


def ensure_can_scan(ctx: AppContext, session: Session, targets: list[str]) -> None:
    """Refuse (with a clear problem) any network work outside the scope, or while stopped. Live mode only."""
    if not ctx.settings.live:
        return
    st = state_row(ctx, session)
    if not st.armed:
        raise ProblemError(409, "safety-stopped", "Stopped by the kill switch",
                           f"Network activity was stopped by {st.changed_by}: {st.reason}. An admin must re-arm.")
    scope = active_scope(session)
    includes = [ipaddress.ip_network(e.cidr) for e in scope if e.kind == "INCLUDE"]
    excludes = [ipaddress.ip_network(e.cidr) for e in scope if e.kind == "EXCLUDE"]
    if not includes:
        raise ProblemError(409, "scan-scope-empty", "No scan scope configured",
                           "Scanning is disabled until an admin adds a subnet under Settings → Scan Scope.")
    for t in targets:
        net = _network(t)
        if not any(net.version == inc.version and net.subnet_of(inc) for inc in includes):
            raise ProblemError(422, "target-out-of-scope", "Target outside the scan scope",
                               f"{net} is not inside an approved scan scope entry")
        if net.num_addresses == 1 and any(net.version == ex.version and net.subnet_of(ex) for ex in excludes):
            raise ProblemError(422, "target-excluded", "Target excluded from the scan scope",
                               f"{net.network_address} is on the exclusion list")


def environment(ctx: AppContext, session: Session) -> schemas.Environment:
    if not ctx.settings.live:
        return schemas.Environment(mode="SIMULATED", banner=SIM_BANNER, severity="info", armed=True, safe_mode=False,
                                   scope=[])
    v = view(ctx, session)
    if not v.armed:
        banner, severity = f"LIVE NETWORK - STOPPED BY KILL SWITCH ({v.changed_by}: {v.reason})", "danger"
    elif not v.scope_configured:
        banner, severity = "LIVE NETWORK - NO SCAN SCOPE CONFIGURED (scanning disabled)", "warning"
    else:
        banner, severity = f"LIVE NETWORK - scope: {', '.join(v.includes)}", "danger"
    if v.safe_mode and v.armed:
        banner += " · SAFE MODE"
    return schemas.Environment(mode="LIVE", banner=banner, severity=severity, armed=v.armed, safe_mode=v.safe_mode,
                               scope=v.includes)
