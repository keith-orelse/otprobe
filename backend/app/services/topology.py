"""Topology graph built from OTProbe's knowledge (assets + observed relationships) plus static zone config."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import schemas
from app.engines.inventory import CONDUIT
from app.models import Asset, AssetField, AssetRelationship, ProbeRun

LEVELS = [("level-dmz", "DMZ (Level 3.5)"), ("level-2", "Level 2 · Supervisory"), ("level-1", "Level 1 · Control"),
          ("level-0", "Level 0 · Process")]
AGENT_ACTIVE = {"ENROLLING", "ONLINE", "STALE", "OFFLINE", "REMOVING", "ERROR"}


def node_state(asset: Asset, last_probe_status: str | None) -> str:
    if asset.is_rogue:
        return "WARNING"
    if asset.status == "OFFLINE":
        return "OFFLINE"
    if asset.agent_state in AGENT_ACTIVE:
        return "AGENT_INSTALLED"
    if last_probe_status == "FAILED":
        return "FAILED"
    if last_probe_status == "PARTIAL":
        return "WARNING"
    if asset.last_probe_at is not None:
        return "AGENTLESS"
    if asset.status == "ONLINE":
        return "ONLINE"
    return "UNKNOWN"


def build(session: Session) -> schemas.Topology:
    nodes = [schemas.TopologyNode(id=i, kind="zone", parent=None, label=label, order=n)
             for n, (i, label) in enumerate(LEVELS)]
    nodes.append(schemas.TopologyNode(id="otprobe-server", kind="server", parent="level-dmz",
                                      label="otprobe-server 192.168.35.72", state="ONLINE", ip="192.168.35.72"))
    nodes.append(schemas.TopologyNode(id=CONDUIT["id"], kind="conduit", parent=None, label=CONDUIT["label"],
                                      state="ONLINE"))
    edges = [schemas.TopologyEdge(id="e-server-conduit", source="otprobe-server", target=CONDUIT["id"],
                                  kind="LINK", protocol="management")]
    assets = list(session.scalars(select(Asset).order_by(Asset.ip_num)))
    last_status: dict[str, str] = {}
    for run in session.scalars(select(ProbeRun).order_by(ProbeRun.created_at)):
        last_status[run.asset_id] = run.status
    rels = list(session.scalars(select(AssetRelationship)))
    link_sources = {r.src_asset_id for r in rels if r.kind == "LINK"}
    for a in assets:
        parent = f"level-{a.level}" if a.level in ("0", "1", "2") else "level-2"
        nodes.append(schemas.TopologyNode(id=a.id, kind="asset", parent=parent, label=a.display_name,
                                          state=node_state(a, last_status.get(a.id)), asset_id=a.id, ip=a.ip,
                                          type=a.device_type,
                                          tier="infrastructure" if a.id in link_sources else "host"))
    for r in rels:
        edges.append(schemas.TopologyEdge(id=f"e-{r.id}", source=r.src_asset_id, target=r.dst_asset_id, kind=r.kind,
                                          protocol=r.protocol, port=r.port))
    # The conduit uplink is seen on the switch port whose LLDP/FDB neighbour is the conduit MAC.
    for f in session.scalars(select(AssetField).where(AssetField.field_path == "network.lldp_neighbors")):
        if any(n.get("mac") == CONDUIT["mac"] for n in f.value or []):
            edges.append(schemas.TopologyEdge(id=f"e-conduit-{f.asset_id}", source=CONDUIT["id"],
                                              target=f.asset_id, kind="LINK", protocol="uplink"))
    return schemas.Topology(nodes=nodes, edges=edges)
