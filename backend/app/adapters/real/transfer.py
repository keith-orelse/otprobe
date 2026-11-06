"""Package transfer (PUSH mode): copies a verified agent build onto the host over the session the deployment engine
opened, WinRM (into C:\\ProgramData\\OTProbe\\staging) or SSH (SFTP into a new private folder under /var/tmp)."""

from __future__ import annotations

from typing import Callable

from app.adapters.base import (
    PackageRef,
    PackageTransfer,
    ProgressCallback,
    Protocol,
    RemoteSession,
    ResultStatus,
    TransferResult,
)
from app.adapters.real.net import winrm
from app.adapters.real.net.gate import GateBlocked

STATUS = {"OK": ResultStatus.OK, "REFUSED": ResultStatus.REFUSED, "TIMEOUT": ResultStatus.TIMEOUT,
          "TLS_INVALID": ResultStatus.TLS_INVALID, "AUTH_FAILED": ResultStatus.AUTH_FAILED,
          "DISABLED": ResultStatus.DISABLED, "BLOCKED": ResultStatus.BLOCKED, "ERROR": ResultStatus.ERROR,
          "NO_ROOT": ResultStatus.ERROR}


class RealPackageTransfer(PackageTransfer):
    """``adapter_for(protocol)`` returns the adapter in use for a protocol (looked up per transfer); ``resolve`` maps
    a package id to the local file of its verified build (both wired in app.main)."""

    def __init__(self, adapter_for: Callable[[Protocol], object], resolve: Callable[[str], str | None]) -> None:
        self.adapter_for, self.resolve = adapter_for, resolve

    async def transfer(self, session: RemoteSession, package: PackageRef,
                       on_progress: ProgressCallback | None = None) -> TransferResult:
        local = self.resolve(package.package_id)
        if not local:
            return TransferResult(ResultStatus.ERROR, error_code="BUILD_NOT_FOUND",
                                  error_detail=f"No verified agent build for package {package.package_id}")
        if on_progress is not None:
            await on_progress(0.0)
        adapter = self.adapter_for(session.protocol)
        try:
            if session.protocol == Protocol.SSH:
                reply = await adapter.copy(session, local)
                status, path, detail = reply.status, reply.stdout.strip(), reply.detail
            else:
                remote = f"{winrm.STAGING}\\{local.rsplit('/', 1)[-1]}".replace("\\\\", "\\")
                reply = await adapter.copy(session, local, remote)
                status, path, detail = reply.status, reply.output, reply.detail
        except GateBlocked as exc:
            return TransferResult(ResultStatus.BLOCKED, error_code="BLOCKED", error_detail=str(exc))
        if status != "OK":
            return TransferResult(STATUS.get(status, ResultStatus.ERROR), error_code=f"COPY_{status}",
                                  error_detail=detail)
        if on_progress is not None:
            await on_progress(1.0)
        return TransferResult(ResultStatus.OK, remote_path=path, bytes_transferred=package.size_bytes)
