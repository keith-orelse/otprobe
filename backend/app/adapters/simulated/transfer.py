"""Simulated package transfer: progress is modelled from bandwidth; the staged file's hash is what a real copy
would produce (or a corrupted one when the package_checksum_mismatch fault is active)."""

from __future__ import annotations

from app.adapters.base import PackageRef, PackageTransfer, ProgressCallback, RemoteSession, ResultStatus, TransferResult
from app.sim.latency import SimLatency
from app.sim.world import SimWorld

CHUNKS = 10
BANDWIDTH_MBPS = 80.0
STAGING_DIR = "C:/ProgramData/OTProbe/staging"


class SimulatedPackageTransfer(PackageTransfer):
    def __init__(self, world: SimWorld, latency: SimLatency, sessions) -> None:
        self.world, self.latency, self._sessions = world, latency, sessions

    async def transfer(self, session: RemoteSession, package: PackageRef,
                       on_progress: ProgressCallback | None = None) -> TransferResult:
        device_id = self._sessions(session)
        if device_id is None:
            return TransferResult(ResultStatus.ERROR, error_code="NO_SESSION", error_detail="WinRM session is closed")
        seconds = package.size_bytes * 8 / (BANDWIDTH_MBPS * 1_000_000)
        for i in range(1, CHUNKS + 1):
            await self.latency.wait(f"xfer:{session.target}:{i}", seconds / CHUNKS, 0.3)
            d = self.world.device(device_id)
            if d is None or not d.online:
                done = package.size_bytes * (i - 1) // CHUNKS
                return TransferResult(ResultStatus.UNREACHABLE, bytes_transferred=done, error_code="CONNECTION_LOST",
                                      error_detail="Host went offline during transfer")
            if on_progress is not None:
                await on_progress(i / CHUNKS)
        corrupted = d.has("package_checksum_mismatch")
        path = f"{STAGING_DIR}/ProbeAgent-{package.version}-x64.msi"
        sha = ("9b07" + package.sha256[4:-4][::-1] + "a4d2") if corrupted else package.sha256

        def stage(state: dict) -> None:
            state.setdefault("files", {}).setdefault("staged", {})[path] = {"sha256": sha, "size": package.size_bytes,
                                                                            "version": package.version}

        self.world.update_state(device_id, stage)
        return TransferResult(ResultStatus.OK, remote_path=path, bytes_transferred=package.size_bytes)
