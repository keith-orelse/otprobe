from __future__ import annotations

from typing import Any, Mapping

from app.adapters.base import SimulationControl
from app.sim.world import SimWorld


class SimulatedControl(SimulationControl):
    def __init__(self, world: SimWorld) -> None:
        self.world = world

    def devices(self) -> list[dict[str, Any]]:
        out = []
        for d in self.world.all_devices():
            agent = d.state.get("files", {}).get("agent")
            out.append({"deviceId": d.device_id, "ip": d.ip, "hostname": d.hostname, "type": d.device_type,
                        "level": d.level, "powered": d.powered, "online": d.online,
                        "agentInstalled": bool(agent), "faults": sorted(d.faults)})
        return out

    def set_fault(self, device_id: str, fault: str, params: Mapping[str, Any], set_by: str) -> None:
        if self.world.device(device_id) is None:
            raise KeyError(device_id)
        self.world.set_fault(device_id, fault, dict(params), set_by)

    def clear_fault(self, device_id: str, fault: str) -> None:
        if self.world.device(device_id) is None:
            raise KeyError(device_id)
        self.world.clear_fault(device_id, fault)
