"""Agentless vs Deep Agent comparison, computed from the provenance store (asset_fields by stage)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import schemas
from app.core.clock import utcnow
from app.core.errors import not_found
from app.models import Agent, Asset, AssetField

NOT_COLLECTED = "Not collected"


def _by_stage(session: Session, asset_id: str) -> dict[str, dict[str, AssetField]]:
    out: dict[str, dict[str, AssetField]] = {"AGENTLESS": {}, "DEEP": {}}
    for f in session.scalars(select(AssetField).where(AssetField.asset_id == asset_id)):
        if f.stage in out:
            cur = out[f.stage].get(f.field_path)
            if cur is None or f.collected_at > cur.collected_at:
                out[f.stage][f.field_path] = f
    return out


def _cell(level: str, value: Any = None, source: str | None = None, detail: str | None = None) -> schemas.CompareCell:
    return schemas.CompareCell(level=level, value=value, source=source, detail=detail)


def _v(fields: dict[str, AssetField], path: str) -> Any:
    f = fields.get(path)
    return f.value if f else None


def _src(fields: dict[str, AssetField], *paths: str) -> str | None:
    return next((fields[p].source for p in paths if p in fields), None)


def _os(fields: dict[str, AssetField]) -> str | None:
    product = _v(fields, "os.product")
    if not product:
        return None
    build = _v(fields, "os.build")
    return f"{product} ({build})" if build else product


def build(session: Session, asset_id: str) -> schemas.Comparison:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise not_found("Asset", asset_id)
    st = _by_stage(session, asset_id)
    al, dp = st["AGENTLESS"], st["DEEP"]
    agent = session.get(Agent, asset.current_agent_id) if asset.current_agent_id else None
    has_deep = bool(dp)
    no_agent = _cell(NOT_COLLECTED, detail="No deep agent evidence for this asset")
    rows: list[schemas.CompareRow] = []

    def row(capability: str, agentless: schemas.CompareCell, deep: schemas.CompareCell) -> None:
        rows.append(schemas.CompareRow(capability=capability, agentless=agentless, deep=deep if has_deep or
                                       capability in ("Continuous monitoring", "Heartbeat") else no_agent))

    ifaces = _v(dp, "network.interfaces") or []
    row("IP address", _cell("Collected" if _v(al, "network.ip") else NOT_COLLECTED, _v(al, "network.ip"),
                            _src(al, "network.ip")),
        _cell("Collected" if ifaces else NOT_COLLECTED, ", ".join(i.get("ip", "") for i in ifaces) or None,
              _src(dp, "network.interfaces")))
    row("Hostname", _cell("Collected" if _v(al, "identity.hostname") else NOT_COLLECTED,
                          _v(al, "identity.hostname"), _src(al, "identity.hostname")),
        _cell("Collected" if _v(dp, "identity.hostname") else NOT_COLLECTED, _v(dp, "identity.hostname"),
              _src(dp, "identity.hostname")))
    row("Operating system", _cell("Collected" if _os(al) else NOT_COLLECTED, _os(al), _src(al, "os.product")),
        _cell("Collected" if _os(dp) else NOT_COLLECTED, _os(dp), _src(dp, "os.product")))
    hw = [p for p in al if p.startswith("hardware.")]
    hw_d = [p for p in dp if p.startswith("hardware.")]
    row("Hardware", _cell("Collected" if hw else NOT_COLLECTED, f"{len(hw)} fields", _src(al, *hw)),
        _cell("Collected" if hw_d else NOT_COLLECTED, f"{len(hw_d)} fields", _src(dp, *hw_d)))

    apps_a = {a["name"] for a in (_v(al, "software.installed") or [])}
    apps_d = {a["name"] for a in (_v(dp, "software.installed") or [])}
    only_deep = sorted(apps_d - apps_a)
    row("Applications",
        _cell("Partial" if apps_a else NOT_COLLECTED, len(apps_a), _src(al, "software.installed"),
              "Machine-scope Uninstall keys only"),
        _cell("Full", len(apps_d), _src(dp, "software.installed"),
              f"Only visible to the agent: {', '.join(only_deep)}" if only_deep else "Includes per-user installs"))
    fw_a, fw_d = _v(al, "firewall.state"), _v(dp, "firewall.state")
    profiles = _v(dp, "firewall.profiles") or {}
    row("Firewall", _cell("Available" if fw_a else NOT_COLLECTED, fw_a, _src(al, "firewall.state"), "On/off only"),
        _cell("Detailed" if fw_d else NOT_COLLECTED, fw_d, _src(dp, "firewall.state"),
              ", ".join(f"{k}={v}" for k, v in profiles.items()) +
              (f"; default inbound {_v(dp, 'firewall.default_inbound')}, {_v(dp, 'firewall.rule_count')} rules"
               if profiles else "")))
    admins = _v(dp, "local_admins.members")
    row("Local administrators", _cell(NOT_COLLECTED),
        _cell("Collected" if admins is not None else NOT_COLLECTED, len(admins or []), _src(dp, "local_admins.members"),
              f"{_v(dp, 'local_admins.enabled_count')} enabled" if admins is not None else None))
    policies_d = [p for p in ("password_policy.min_length", "audit.logon_events", "usb.storage_policy") if p in dp]
    av_a = _v(al, "antivirus.state")
    row("Security policies", _cell("Limited", f"antivirus {av_a}" if av_a else None, _src(al, "antivirus.state"),
                                   "Antivirus state only; no password, audit or USB policy"),
        _cell("Collected" if policies_d else NOT_COLLECTED, len(policies_d), "DEEP_AGENT" if policies_d else None,
              "password policy, audit configuration" + ("" if "usb.storage_policy" in dp
                                                        else "; USB policy unverifiable on host")))
    online = agent is not None and agent.status == "ONLINE"
    row("Continuous monitoring", _cell("No", detail="Point-in-time probes only"),
        _cell("Yes" if online else "No", agent.status if agent else None, None,
              "Scheduled assessments and heartbeats" if online else "No online agent"))
    since = int((utcnow() - agent.last_heartbeat_at).total_seconds()) if agent and agent.last_heartbeat_at else None
    row("Heartbeat", _cell("N/A"),
        _cell("Yes" if since is not None else "No", f"{since} s ago" if since is not None else None, None,
              agent.status if agent else "No agent"))
    return schemas.Comparison(asset_id=asset.id, asset_name=asset.display_name, has_deep_evidence=has_deep, rows=rows)
