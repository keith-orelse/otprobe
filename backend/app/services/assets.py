from __future__ import annotations

from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app import schemas
from app.adapters.base import Protocol
from app.adapters.registry import AdapterRegistry
from app.core import audit, events
from app.core.errors import ProblemError, not_found
from app.core.fields import GROUP_OF, GROUPS
from app.engines.inventory import effective_fields
from app.models import Asset, AssetField, AssetRelationship, ProbeRun, Zone
from app.services.assessments import compliance
from app.services.common import paginate
from app.services.deployments import deploy_action_for_asset

SORTABLE = {"ip": Asset.ip_num, "hostname": Asset.display_name, "lastSeen": Asset.last_seen, "level": Asset.level,
            "status": Asset.status, "type": Asset.device_type, "criticality": Asset.criticality}


def _source_label(registry: AdapterRegistry, source: str) -> str:
    try:
        return registry.get(Protocol(source)).descriptor().display_label
    except (ValueError, RuntimeError):
        return "Deep agent" if source == "DEEP_AGENT" else source


def field_value(registry: AdapterRegistry, row: AssetField) -> schemas.FieldValue:
    return schemas.FieldValue(path=row.field_path, value=row.value, source=row.source,
                              source_label=_source_label(registry, row.source), stage=row.stage,
                              collected_at=row.collected_at)


def list_assets(session: Session, limit: int, cursor: str | None, q: str | None, status: str | None,
                level: str | None, sort: str | None) -> schemas.Page:
    stmt = select(Asset)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Asset.ip.like(like), Asset.mac.like(like), Asset.display_name.like(like),
                              Asset.device_type.like(like)))
    if status:
        stmt = stmt.where(Asset.status == status)
    if level:
        stmt = stmt.where(Asset.level == level)
    key = (sort or "ip").lstrip("-")
    if key not in SORTABLE:
        raise ProblemError(422, "invalid-sort", "Invalid sort field", f"Sortable: {', '.join(SORTABLE)}")
    col = SORTABLE[key]
    order = col.desc() if (sort or "").startswith("-") else col.asc()
    rows, nxt, total = paginate(session, stmt.order_by(order, Asset.id), limit, cursor)
    return schemas.Page[schemas.AssetSummary](items=[schemas.AssetSummary.model_validate(a) for a in rows],
                                              next_cursor=nxt, total=total)




def get_asset(ctx, session: Session, registry: AdapterRegistry, asset_id: str) -> schemas.AssetDetail:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise not_found("Asset", asset_id)
    running = session.scalar(select(ProbeRun.id).where(ProbeRun.asset_id == asset.id,
                                                       ProbeRun.status.in_(["QUEUED", "RUNNING"])))
    agentless = (schemas.ActionState(enabled=False, reason="An agentless probe is already running")
                 if running else schemas.ActionState(enabled=True, reason="Supported"))
    out = schemas.AssetDetail.model_validate({**schemas.AssetSummary.model_validate(asset).model_dump(),
                                              "deploy_agent": deploy_action_for_asset(session, asset),
                                              "agentless": agentless})
    if asset.zone_id:
        out.zone = schemas.Zone.model_validate(session.get(Zone, asset.zone_id))
    if asset.classification:
        out.classification = schemas.Classification.model_validate(asset.classification)
    eff = effective_fields(session, asset.id)
    order = {p: i for i, p in enumerate(p for paths in GROUPS.values() for p in paths)}
    groups: dict[str, list[schemas.FieldValue]] = {g: [] for g in GROUPS}
    for path in sorted(eff, key=lambda p: order.get(p, 999)):
        groups[GROUP_OF.get(path, "Other")].append(field_value(registry, eff[path]))
    out.groups = {g: v for g, v in groups.items() if v}
    rels = []
    names = {a.id: a.display_name for a in session.scalars(select(Asset))}
    for r in session.scalars(select(AssetRelationship).where(or_(AssetRelationship.src_asset_id == asset.id,
                                                                 AssetRelationship.dst_asset_id == asset.id))):
        outbound = r.src_asset_id == asset.id
        peer = r.dst_asset_id if outbound else r.src_asset_id
        rels.append(schemas.Relationship(kind=r.kind, direction="outbound" if outbound else "inbound",
                                         peer_asset_id=peer, peer_name=names.get(peer, peer), protocol=r.protocol,
                                         port=r.port, source=r.source))
    out.relationships = rels
    last = session.scalar(select(ProbeRun.id).where(ProbeRun.asset_id == asset.id)
                          .order_by(ProbeRun.created_at.desc()).limit(1))
    out.last_probe_id = last
    out.maintenance_window_required = asset.eligibility == "REVIEW_REQUIRED"
    out.current_agent_id = asset.current_agent_id
    out.compliance = compliance(ctx, session, asset)
    reach = eff.get("reachability.icmp")
    if reach is not None and reach.value in ("BLOCKED", "TIMEOUT"):
        out.notes.append("No ICMP reply does not mean the device is offline."
                         + (" This device answered ARP." if "ARP" in (asset.discovered_by or []) or
                            asset.status == "ONLINE" else ""))
    if asset.zone_id and out.zone and out.zone.safe_mode:
        out.notes.append("Safe mode zone (Level 0/1): discovery and probing are passive/read-only and rate-limited.")
    return out


def list_fields(session: Session, registry: AdapterRegistry, asset_id: str, stage: str | None
                ) -> list[schemas.FieldValue]:
    if session.get(Asset, asset_id) is None:
        raise not_found("Asset", asset_id)
    stmt = select(AssetField).where(AssetField.asset_id == asset_id).order_by(AssetField.field_path,
                                                                             AssetField.source)
    if stage:
        stmt = stmt.where(AssetField.stage == stage)
    return [field_value(registry, r) for r in session.scalars(stmt)]


TRUST_FIELDS = ("ssh.host_key", "services.winrm.cert_sha256")


def reset_trust(session: Session, asset_id: str, reason: str, actor) -> tuple[dict[str, Any], None]:
    """Forget the SSH host key and WinRM certificate pinned for an asset (e.g. after a legitimate reinstall). The next
    probe pins whatever the host presents then, so an admin should check the host first. Audited with the old values."""
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise not_found("Asset", asset_id)
    rows = list(session.scalars(select(AssetField).where(AssetField.asset_id == asset_id,
                                                         AssetField.field_path.in_(TRUST_FIELDS))))
    if not rows:
        raise ProblemError(409, "nothing-pinned", "Nothing to reset", "No SSH host key or WinRM certificate is pinned")
    cleared = {r.field_path: r.value for r in rows}
    for r in rows:
        session.delete(r)
    audit.record(session, actor, "ASSET_TRUST_RESET", "asset", asset_id, {"reason": reason, "cleared": cleared})
    events.stage(session, "asset.updated", "asset", asset_id, {})
    return {"assetId": asset_id, "cleared": sorted(cleared)}, None
