"""Placeholders for protocols whose real adapter arrives in a later phase (docs/LIVE_ARCHITECTURE.md §9).
They send nothing and answer NOT_SUPPORTED, so engines skip those steps with a clear message."""

from __future__ import annotations

from typing import Any, AsyncIterator, Awaitable, Callable, Mapping

from app.adapters.base import (
    AdapterDescriptor,
    AdapterResult,
    DiscoveredHost,
    MqttAdapter,
    MqttMessage,
    PackageRef,
    PackageTransfer,
    ProgressCallback,
    Protocol,
    Query,
    RemoteOperation,
    RemoteSession,
    ResultStatus,
    SshAdapter,
    StageCallback,
    Target,
    TransferResult,
    WinRmAdapter,
    WmiAdapter,
)
from app.core.clock import utcnow

PHASE = {Protocol.WINRM: "L3", Protocol.WMI: "L3", Protocol.SSH: "L3", Protocol.MQTT: "L5"}


class _Unavailable:
    protocol: Protocol

    def descriptor(self) -> AdapterDescriptor:
        return AdapterDescriptor(self.protocol, "unavailable", False, f"{self.protocol.value} (not yet available)")

    def _nope(self, target: str) -> AdapterResult:
        return AdapterResult(self.protocol, target, ResultStatus.NOT_SUPPORTED, collected_at=utcnow(),
                             latency_ms=0.0, error_code="NOT_AVAILABLE",
                             error_detail=f"Live {self.protocol.value} arrives in phase {PHASE[self.protocol]}")

    async def discover(self, target: Target) -> AsyncIterator[DiscoveredHost]:
        return
        yield  # pragma: no cover - makes this an async generator

    async def probe(self, target: Target, query: Query, on_stage: StageCallback | None = None) -> AdapterResult:
        return self._nope(target.address)

    async def health_check(self, target: Target) -> AdapterResult:
        return self._nope(target.address)

    async def get_device_info(self, target: Target) -> AdapterResult:
        return self._nope(target.address)


class UnavailableWinRm(_Unavailable, WinRmAdapter):
    protocol = Protocol.WINRM

    async def open_session(self, target: Target, on_stage: StageCallback | None = None):
        return self._nope(target.address), None

    async def execute(self, session: RemoteSession, op: RemoteOperation, params: Mapping[str, Any]) -> AdapterResult:
        return self._nope(session.target)

    async def close_session(self, session: RemoteSession) -> None:
        return None


class UnavailableWmi(_Unavailable, WmiAdapter):
    protocol = Protocol.WMI


class UnavailableSsh(_Unavailable, SshAdapter):
    protocol = Protocol.SSH


class UnavailableMqtt(_Unavailable, MqttAdapter):
    protocol = Protocol.MQTT

    async def subscribe(self, topic_filter: str, handler: Callable[[MqttMessage], Awaitable[None]]) -> str:
        return "unavailable"

    async def unsubscribe(self, subscription_id: str) -> None:
        return None

    async def clients(self) -> list[dict[str, Any]]:
        return []


class UnavailableTransfer(PackageTransfer):
    async def transfer(self, session: RemoteSession, package: PackageRef,
                       on_progress: ProgressCallback | None = None) -> TransferResult:
        return TransferResult(ResultStatus.NOT_SUPPORTED, error_code="NOT_AVAILABLE",
                              error_detail="Live agent deployment arrives in phase L4")
