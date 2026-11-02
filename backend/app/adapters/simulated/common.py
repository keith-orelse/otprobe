from __future__ import annotations

from typing import Any

from app.adapters.base import AdapterDescriptor, AdapterResult, Credential, Protocol, ResultStatus, Stage
from app.core.clock import utcnow
from app.sim.latency import SimLatency
from app.sim.world import DeviceView, SimWorld


class SimAdapterMixin:
    protocol: Protocol
    label: str

    def __init__(self, world: SimWorld, latency: SimLatency) -> None:
        self.world, self.latency = world, latency

    def descriptor(self) -> AdapterDescriptor:
        return AdapterDescriptor(self.protocol, "simulated", True, self.label)

    def result(self, target: str, status: ResultStatus, data: dict[str, Any] | None = None,
               raw: dict[str, Any] | None = None, stages: list[Stage] | None = None, latency_ms: float | None = None,
               error_code: str | None = None, error_detail: str | None = None) -> AdapterResult:
        return AdapterResult(protocol=self.protocol, target=target, status=status, data=data or {}, raw=raw or {},
                             stages=stages or [], latency_ms=round(latency_ms, 2) if latency_ms is not None else 0.0,
                             collected_at=utcnow(), error_code=error_code, error_detail=error_detail)

    async def step_wait(self, key: str, base: float, safe_mode: bool = False) -> float:
        # Safe mode (Level 0/1): at most 1 operation per second per host (a floor, never jittered below).
        if safe_mode:
            delay = max(1.0, self.latency.jitter(key, base))
            await self.latency.pacer.sleep(delay)
            return delay
        return await self.latency.wait(key, base)


def account_ok(device: DeviceView, credential: Credential | None) -> bool:
    if credential is None:
        return False
    return device.state.get("accounts", {}).get(credential.username) == credential.secret


def winrm_gate(device: DeviceView | None, ip: str, credential: Credential | None) -> tuple[str, ResultStatus, str]:
    """Shared WinRM/CIM connection logic. Returns (failing_stage or "", status, detail)."""
    if device is None:
        return "CONNECTING", ResultStatus.TIMEOUT, f"No response from {ip}:5986 (connection timed out)"
    if not device.online:
        return "CONNECTING", ResultStatus.UNREACHABLE, f"Host {ip} unreachable"
    w = device.state.get("winrm")
    if device.has("winrm_timeout"):
        return "CONNECTING", ResultStatus.TIMEOUT, "WinRM connection timed out after 5 s"
    if w is None or device.has("winrm_refused"):
        return "CONNECTING", ResultStatus.REFUSED, f"Connection refused on {ip}:5986"
    if not w.get("enabled", False) or device.has("winrm_disabled"):
        return "CONNECTING", ResultStatus.DISABLED, "WinRM service is disabled on target (5986 refused by service)"
    if w.get("cert") != "valid" or device.has("winrm_bad_certificate"):
        cn = w.get("cert_cn", ip).split(".")[0]
        return ("TLS_VALIDATED", ResultStatus.TLS_INVALID,
                f"TLS certificate validation failed: certificate not trusted (CN={cn}-selfsigned)")
    if device.has("winrm_bad_credentials") or not account_ok(device, credential):
        profile = credential.profile if credential else "none"
        user = credential.username if credential else "none"
        return "AUTH_OK", ResultStatus.AUTH_FAILED, f"Authentication failed for profile {profile} ({user})"
    return "", ResultStatus.OK, "Session created"
