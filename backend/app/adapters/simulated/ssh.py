from __future__ import annotations

from typing import AsyncIterator

from app.adapters.base import AdapterResult, DiscoveredHost, Query, ResultStatus, SshAdapter, StageCallback, Target
from app.adapters.simulated.common import SimAdapterMixin, account_ok


class SimulatedSshAdapter(SimAdapterMixin, SshAdapter):
    """Stub: identity only (hostname, os-release, kernel, uptime)."""

    label = "SSH (Demo stub)"

    async def probe(self, target: Target, query: Query, on_stage: StageCallback | None = None) -> AdapterResult:
        await self.latency.wait(f"ssh:{target.address}", 0.3)
        d = self.world.device_by_ip(target.address)
        if d is None or not d.online:
            return self.result(target.address, ResultStatus.UNREACHABLE, error_code="UNREACHABLE",
                               error_detail=f"No route to {target.address}:22")
        if d.state.get("ssh") is None:
            return self.result(target.address, ResultStatus.REFUSED, {"services.ssh.available": False},
                               error_code="REFUSED", error_detail=f"Connection refused on {target.address}:22")
        if not account_ok(d, target.credential):
            return self.result(target.address, ResultStatus.AUTH_FAILED, {"services.ssh.available": True},
                               error_code="AUTH_FAILED", error_detail="Permission denied (publickey,password)")
        o = d.state["os"]
        data = {"services.ssh.available": True, "identity.hostname": d.state["identity"]["hostname"],
                "os.family": o["family"], "os.name": o["name"], "os.product": o["product"],
                "os.version": o["version"], "os.kernel": o.get("kernel"),
                "hardware.uptime_sec": d.state.get("hardware", {}).get("uptime_sec")}
        return self.result(target.address, ResultStatus.OK, data,
                           raw={"commands": ["hostname", "cat /etc/os-release", "uname -r", "cat /proc/uptime"]})

    async def discover(self, target: Target) -> AsyncIterator[DiscoveredHost]:
        return
        yield  # pragma: no cover

    async def health_check(self, target: Target) -> AdapterResult:
        return await self.probe(target, Query(["identity"]))

    async def get_device_info(self, target: Target) -> AdapterResult:
        return await self.probe(target, Query(["identity"]))
