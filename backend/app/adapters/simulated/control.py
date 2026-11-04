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
                        "agentInstalled": bool(agent), "faults": sorted(d.faults),
                        "config": self._config(d.state)})
        return out

    @staticmethod
    def _config(state: dict) -> dict[str, str]:
        """Current value of each configuration control that applies to this host (Windows only)."""
        if state.get("os", {}).get("family") != "windows":
            return {}
        names = {"AnyRemote Demo", "RemoteTool Demo"}
        return {"firewall": state["firewall"]["state"], "antivirus": state["antivirus"]["state"],
                "unauthorized_software": "installed" if any(a["name"] in names for a in state["software"])
                else "none",
                "remove_patch": f"{len(state['patches']['missing'])} missing"}

    def set_fault(self, device_id: str, fault: str, params: Mapping[str, Any], set_by: str) -> None:
        if self.world.device(device_id) is None:
            raise KeyError(device_id)
        self.world.set_fault(device_id, fault, dict(params), set_by)

    def clear_fault(self, device_id: str, fault: str) -> None:
        if self.world.device(device_id) is None:
            raise KeyError(device_id)
        self.world.clear_fault(device_id, fault)

    def apply_config(self, device_id: str, control: str, value: str) -> str:
        d = self.world.device(device_id)
        if d is None:
            raise KeyError(device_id)
        if d.state.get("os", {}).get("family") != "windows":
            raise ValueError(f"{control} applies to Windows hosts only")
        if control == "remove_patch" and not d.state["patches"]["installed"]:
            raise ValueError("no installed patches left to remove")
        effect: list[str] = []

        def mutate(state: dict) -> None:
            if control == "firewall":
                on = "on" if value == "enabled" else "off"
                state["firewall"]["state"] = value
                state["firewall"]["profiles"] = {k: on for k in state["firewall"].get("profiles", {})}
                effect.append(f"firewall {value} on all profiles")
            elif control == "antivirus":
                state["antivirus"]["state"] = value
                svc = next((s for s in state["services"] if s["name"] == "WinDefend"), None)
                if svc:
                    svc["state"] = "running" if value == "running" else "stopped"
                effect.append(f"antivirus {value}")
            elif control == "unauthorized_software":
                names = {"AnyRemote Demo", "RemoteTool Demo"}
                if value == "install":
                    state["software"].append({"name": "AnyRemote Demo", "version": "1.0.0", "publisher": "Demo Corp",
                                              "scope": "machine"})
                    effect.append("installed AnyRemote Demo 1.0.0 (machine scope)")
                else:
                    removed = [a["name"] for a in state["software"] if a["name"] in names]
                    state["software"] = [a for a in state["software"] if a["name"] not in names]
                    effect.append(f"removed {', '.join(removed) or 'nothing'}")
            elif control == "remove_patch":
                kb = state["patches"]["installed"].pop()
                state["patches"]["missing"].append(kb)
                effect.append(f"uninstalled {kb} (now missing)")

        self.world.update_state(device_id, mutate)
        return effect[0]
