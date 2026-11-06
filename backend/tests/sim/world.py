"""Access to the simulated world (ground truth). Used by simulated adapters and the /sim API only."""

from __future__ import annotations

import ipaddress
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Callable

from sqlalchemy import delete, select

from app.core.db import Database
from tests.sim import seed_data
from tests.sim.models import SimDevice, SimFault, SimMeta, SimMqttClient


@dataclass(frozen=True)
class DeviceView:
    device_id: str
    ip: str
    mac: str
    hostname: str
    vendor: str
    model: str
    device_type: str
    level: str
    powered: bool
    state: dict[str, Any]
    faults: dict[str, dict[str, Any]] = field(default_factory=dict)

    def has(self, fault: str) -> bool:
        return fault in self.faults

    @property
    def online(self) -> bool:
        return self.powered and not self.has("device_offline") and not self.has("plc_offline")


def _view(d: SimDevice, faults: dict[str, dict[str, Any]]) -> DeviceView:
    return DeviceView(d.device_id, d.ip, d.mac, d.hostname, d.vendor, d.model, d.device_type, d.level, d.powered,
                      deepcopy(d.state), faults)


def _ip_key(ip: str) -> int:
    return int(ipaddress.ip_address(ip))


class SimWorld:
    def __init__(self, db: Database) -> None:
        self.db = db

    def _faults(self, s, device_id: str) -> dict[str, dict[str, Any]]:
        rows = s.scalars(select(SimFault).where(SimFault.device_id.in_([device_id, "*"])))
        return {r.fault: r.params for r in rows}

    def device(self, device_id: str) -> DeviceView | None:
        with self.db.session() as s:
            d = s.get(SimDevice, device_id)
            return _view(d, self._faults(s, d.device_id)) if d else None

    def device_by_ip(self, ip: str) -> DeviceView | None:
        with self.db.session() as s:
            d = s.scalar(select(SimDevice).where(SimDevice.ip == ip))
            return _view(d, self._faults(s, d.device_id)) if d else None

    def devices_in(self, cidr: str) -> list[DeviceView]:
        net = ipaddress.ip_network(cidr, strict=False)
        with self.db.session() as s:
            rows = [d for d in s.scalars(select(SimDevice)) if ipaddress.ip_address(d.ip) in net]
            return [_view(d, self._faults(s, d.device_id)) for d in sorted(rows, key=lambda d: _ip_key(d.ip))]

    def all_devices(self) -> list[DeviceView]:
        with self.db.session() as s:
            rows = sorted(s.scalars(select(SimDevice)), key=lambda d: _ip_key(d.ip))
            return [_view(d, self._faults(s, d.device_id)) for d in rows]

    def update_state(self, device_id: str, mutate: Callable[[dict[str, Any]], None]) -> None:
        with self.db.session() as s:
            d = s.get(SimDevice, device_id)
            if d is None:
                raise KeyError(device_id)
            state = deepcopy(d.state)
            mutate(state)
            d.state = state

    def set_power(self, device_id: str, powered: bool) -> None:
        with self.db.session() as s:
            d = s.get(SimDevice, device_id)
            if d is None:
                raise KeyError(device_id)
            d.powered = powered

    def set_fault(self, device_id: str, fault: str, params: dict[str, Any] | None = None,
                  set_by: str = "simulator") -> None:
        with self.db.session() as s:
            row = s.scalar(select(SimFault).where(SimFault.device_id == device_id, SimFault.fault == fault))
            if row is None:
                s.add(SimFault(device_id=device_id, fault=fault, params=params or {}, set_by=set_by))
            else:
                row.params = params or {}

    def clear_fault(self, device_id: str, fault: str) -> None:
        with self.db.session() as s:
            s.execute(delete(SimFault).where(SimFault.device_id == device_id, SimFault.fault == fault))

    def mqtt_clients(self) -> list[dict[str, Any]]:
        with self.db.session() as s:
            return [{"client_id": c.client_id, "device_id": c.device_id, "source_ip": c.source_ip,
                     "connected": c.connected, "topics": list(c.topics)} for c in s.scalars(select(SimMqttClient))]

    def inject_rogue(self) -> DeviceView:
        with self.db.session() as s:
            meta = s.get(SimMeta, "rogue_counter")
            n = (meta.value if meta else 0) + 1
            if meta is None:
                s.add(SimMeta(key="rogue_counter", value=n))
            else:
                meta.value = n
            t = seed_data.ROGUE_TEMPLATE
            octet = 65 + n
            ip = f"192.168.20.{octet}"
            mac = f"DE:AD:BE:EF:20:{octet:02d}" if octet < 100 else f"DE:AD:BE:EF:21:{octet - 100:02d}"
            d = SimDevice(device_id=f"dev-rogue-{n}", ip=ip, mac=mac, hostname=t["hostname"], vendor=t["vendor"],
                          model=t["model"], device_type=t["device_type"], level=t["level"], powered=True,
                          state=deepcopy(t["state"]))
            s.add(d)
            s.flush()
            return _view(d, {})
