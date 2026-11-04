"""Inventory writes shared by discovery and probing: merge-by-MAC, provenance upserts, effective values,
classification refresh and relationships (docs/PROVENANCE.md)."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit, events
from app.core.audit import Actor
from app.core.clock import utcnow
from app.core.fields import PROVENANCE_FIELDS, STAGE_RANK
from app.engines.classification import classify, eligibility
from app.models import Asset, AssetField, AssetRelationship, Zone
from app.rules.book import RuleBook
from app.rules.conditions import nest

CONDUIT = {"id": "fw-conduit-01", "label": "fw-conduit-01 (conduit)", "mac": "00:1A:2B:3C:FE:01"}


def zone_for_ip(session: Session, ip: str) -> Zone | None:
    addr = ipaddress.ip_address(ip)
    for z in session.scalars(select(Zone)):
        if addr in ipaddress.ip_network(z.cidr):
            return z
    return None


def upsert_fields(session: Session, asset_id: str, data: dict[str, Any], source: str, stage: str, run_kind: str,
                  run_id: str, collected_at: datetime | None = None) -> int:
    at = collected_at or utcnow()
    n = 0
    for path, value in data.items():
        if path not in PROVENANCE_FIELDS or value is None:
            continue
        row = session.scalar(select(AssetField).where(AssetField.asset_id == asset_id, AssetField.field_path == path,
                                                      AssetField.source == source))
        if row is None:
            session.add(AssetField(asset_id=asset_id, field_path=path, value=value, source=source, stage=stage,
                                   collected_at=at, run_kind=run_kind, run_id=run_id))
        else:
            row.value, row.stage, row.collected_at, row.run_kind, row.run_id = value, stage, at, run_kind, run_id
        n += 1
    session.flush()
    return n


def effective_fields(session: Session, asset_id: str) -> dict[str, AssetField]:
    best: dict[str, AssetField] = {}
    for row in session.scalars(select(AssetField).where(AssetField.asset_id == asset_id)):
        cur = best.get(row.field_path)
        key = (row.collected_at, STAGE_RANK[row.stage])
        if cur is None or key > (cur.collected_at, STAGE_RANK[cur.stage]):
            best[row.field_path] = row
    return best


def _os_label(flat: dict[str, Any]) -> str | None:
    product = flat.get("os.product") or flat.get("os.name")
    if not product:
        return None
    version, build = flat.get("os.version"), flat.get("os.build")
    label = product + (f" {version}" if version and version not in product else "")
    return label + (f" ({build})" if build else "")


def refresh_asset(session: Session, asset: Asset, book: RuleBook) -> dict[str, Any] | None:
    """Recompute denormalised columns, classification and eligibility from effective provenance fields."""
    eff = effective_fields(session, asset.id)
    flat = {p: r.value for p, r in eff.items()}
    doc = nest(flat)
    asset.ip = flat.get("network.ip", asset.ip)
    asset.hostname = flat.get("identity.hostname")
    asset.sys_name = flat.get("snmp.sys_name")
    asset.os_name = _os_label(flat)
    asset.display_name = asset.hostname or asset.sys_name or flat.get("mqtt.client_id") or asset.ip
    zone = session.get(Zone, asset.zone_id) if asset.zone_id else None
    cls = classify(doc, book)
    if cls is not None:
        asset.device_type = cls.type
        asset.classification = cls.as_dict()
        if asset.criticality_source != "MANUAL":
            asset.criticality = cls.default_criticality
        asset.level = cls.level_hint
    else:
        asset.device_type, asset.classification = None, None
        asset.level = zone.default_level if zone else asset.level
    elig_doc = {**doc, "classification": {"type": asset.device_type},
                "asset": {"criticality": asset.criticality}}
    asset.eligibility, asset.eligibility_reason = eligibility(elig_doc, book)
    record_relationships(session, asset, flat, eff)
    events.stage(session, "asset.updated", "asset", asset.id, {"ip": asset.ip, "status": asset.status})
    return asset.classification


def _upsert_rel(session: Session, src: str, dst: str, kind: str, protocol: str, port: int | None,
                source: str) -> None:
    row = session.scalar(select(AssetRelationship).where(
        AssetRelationship.src_asset_id == src, AssetRelationship.dst_asset_id == dst,
        AssetRelationship.kind == kind, AssetRelationship.protocol == protocol, AssetRelationship.port == port))
    if row is None:
        session.add(AssetRelationship(src_asset_id=src, dst_asset_id=dst, kind=kind, protocol=protocol, port=port,
                                      source=source))
    else:
        row.last_seen = utcnow()


def record_relationships(session: Session, asset: Asset, flat: dict[str, Any], eff: dict[str, AssetField]) -> None:
    by_ip = {a.ip: a for a in session.scalars(select(Asset))}
    by_mac = {a.mac: a for a in by_ip.values() if a.mac}
    for conn in flat.get("network.connections") or []:
        dst = by_ip.get(conn.get("remote_ip"))
        if dst is not None and dst.id != asset.id:
            _upsert_rel(session, asset.id, dst.id, "FLOW", conn.get("protocol", "tcp"), conn.get("remote_port"),
                        eff["network.connections"].source)
    for n in flat.get("network.lldp_neighbors") or []:
        dst = by_mac.get(n.get("mac"))
        if dst is not None and dst.id != asset.id:
            m = re.search(r"(\d+)$", n.get("port", ""))
            _upsert_rel(session, asset.id, dst.id, "LINK", n.get("port", "port"), int(m.group(1)) if m else None,
                        eff["network.lldp_neighbors"].source)
    broker = flat.get("mqtt.broker")
    if broker:
        dst = by_ip.get(broker.split(":")[0])
        if dst is not None and dst.id != asset.id:
            _upsert_rel(session, asset.id, dst.id, "FLOW", "MQTT-TLS", int(broker.split(":")[1]), "MQTT")
    session.flush()


def merge_observation(session: Session, ip: str, mac: str | None, actor: Actor, baseline_zone_ids: set[str]
                      ) -> tuple[Asset, bool, bool]:
    """Find-or-create by MAC, falling back to IP. Returns (asset, created, rogue).

    Live discovery sees hosts by IP first (ICMP/TCP) and learns the MAC from the neighbour table afterwards; hosts
    on remote subnets never have a MAC. So: a known MAC wins; otherwise an asset at the same IP with no MAC yet
    adopts the MAC; an IP-only observation matches by IP."""
    asset = session.scalar(select(Asset).where(Asset.mac == mac)) if mac else None
    if asset is None:
        by_ip = session.scalar(select(Asset).where(Asset.ip == ip, Asset.mac.is_(None)) if mac
                               else select(Asset).where(Asset.ip == ip))
        if by_ip is not None:
            if mac:
                by_ip.mac = mac
                audit.record(session, actor, "ASSET_MAC_LEARNED", "asset", by_ip.id, {"ip": ip, "mac": mac})
            by_ip.status, by_ip.last_seen = "ONLINE", utcnow()
            return by_ip, False, False
    now = utcnow()
    if asset is None:
        zone = zone_for_ip(session, ip)
        rogue = zone is not None and zone.id in baseline_zone_ids
        asset = Asset(mac=mac, ip=ip, display_name=ip, level=zone.default_level if zone else "?",
                      zone_id=zone.id if zone else None, status="ONLINE", is_rogue=rogue, authorized=not rogue,
                      first_seen=now, last_seen=now, discovered_by=[])
        session.add(asset)
        session.flush()
        audit.record(session, actor, "ASSET_CREATED", "asset", asset.id, {"ip": ip, "mac": mac})
        if rogue:
            who = f"unknown MAC {mac}" if mac else "unknown device"
            audit.record(session, actor, "ROGUE_DEVICE_DETECTED", "asset", asset.id,
                         {"ip": ip, "mac": mac, "message": f"Rogue device: {who} at {ip}"})
            events.stage(session, "asset.rogue", "asset", asset.id, {"ip": ip, "mac": mac})
        return asset, True, rogue
    if asset.ip != ip:
        audit.record(session, actor, "ASSET_IP_CHANGED", "asset", asset.id, {"from": asset.ip, "to": ip, "mac": mac})
        asset.ip = ip
    conflict = session.scalar(select(Asset).where(Asset.ip == ip, Asset.id != asset.id))
    if conflict is not None:
        audit.record(session, actor, "IP_MAC_CONFLICT", "asset", asset.id,
                     {"ip": ip, "mac": mac, "otherAssetId": conflict.id, "otherMac": conflict.mac})
    asset.status, asset.last_seen = "ONLINE", now
    return asset, False, False
