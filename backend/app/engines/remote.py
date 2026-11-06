"""Helpers shared by the engines that act on a host to install, restart or remove the agent (precheck, deployment,
removal, restart): over WinRM on Windows, over SSH on Linux."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app.adapters.base import Protocol, ResultStatus
from app.context import AppContext
from app.engines.protocol_events import winrm_event
from app.models import Agent, Deployment


@dataclass(frozen=True)
class Platform:
    os: str                     # os.family of the hosts it serves
    protocol: Protocol          # how OTProbe reaches the host to install the agent
    access: str                 # name used in precheck checks and deploy steps: WINRM_AVAILABLE, SSH_SESSION, ...
    label: str
    installer_profile: str      # default vault profile for install / removal / restart
    port: int
    service: str                # the agent's service name on the host
    staging: str                # what removal asks the adapter to clean up
    hash_command: str           # shown in the VERIFY_HASH step

    def options(self, fields: dict[str, Any]) -> dict[str, Any]:
        """Session options: install, removal and restart sessions only log in to the host whose SSH key or WinRM
        certificate an earlier probe pinned (no pin, no login)."""
        if self.protocol == Protocol.SSH:
            return {"host_key": fields.get("ssh.host_key")}
        return {"cert_sha256": fields.get("services.winrm.cert_sha256"), "require_cert_pin": True}

    def event(self, status: ResultStatus, code: str | None = None) -> str:
        if self.protocol == Protocol.SSH:
            return SSH_EVENTS.get(status, f"SSH_{status.value}")
        return "WINRM_CERT_CHANGED" if code == "CERT_CHANGED" else winrm_event(status)


SSH_EVENTS = {ResultStatus.REFUSED: "SSH_CONNECTION_REFUSED", ResultStatus.TIMEOUT: "SSH_TIMEOUT",
              ResultStatus.AUTH_FAILED: "SSH_AUTH_FAILED", ResultStatus.TLS_INVALID: "SSH_HOST_KEY_CHANGED",
              ResultStatus.UNREACHABLE: "ASSET_UNREACHABLE"}
WINDOWS = Platform("windows", Protocol.WINRM, "WINRM", "WinRM", "OT-WINDOWS-INSTALLER", 5986, "OTProbeAgent",
                   "C:/ProgramData/OTProbe/staging", "Get-FileHash -Algorithm SHA256")
LINUX = Platform("linux", Protocol.SSH, "SSH", "SSH", "OT-LINUX-SSH-INSTALLER", 22, "otprobe-agent",
                 "/var/tmp/otprobe.*", "sha256sum")


def platform_for(fields: dict[str, Any]) -> Platform:
    return LINUX if fields.get("os.family") == "linux" else WINDOWS


def installer_profile(session: Session, agent: Agent, platform: Platform) -> str:
    """Removal and restart use the vault profile the agent was installed with (else the platform's default)."""
    dep = session.get(Deployment, agent.deployment_id) if agent.deployment_id else None
    return dep.credential_profile if dep is not None and dep.credential_profile else platform.installer_profile


async def profile_port(ctx: AppContext, profile: str, default: int = 5986) -> int:
    """A credential profile's non-standard service port (params.port), read without retrieving the secret."""
    try:
        return (await ctx.vault.describe(profile)).port or default
    except KeyError:
        return default


def server_url(ctx: AppContext) -> str:
    """The address agents use to reach OTProbe (OTPROBE_PUBLIC_URL, else AGENT_SERVER_URL)."""
    return (ctx.settings.public_url or ctx.settings.agent_server_url).rstrip("/")


def server_endpoint(ctx: AppContext) -> tuple[str, int]:
    u = urlsplit(server_url(ctx))
    return u.hostname or "", u.port or (443 if u.scheme == "https" else 80)


def agent_profile(fields: dict[str, Any]) -> str:
    """Which collector profile the agent runs (rules/agent_profiles in docs/GO_AGENT.md §2)."""
    family = fields.get("os.family")
    name = f"{fields.get('os.name') or ''} {fields.get('os.product') or ''}"
    if family == "windows":
        return "windows-server" if "Server" in name else "windows-workstation"
    if family == "linux":
        return "linux-host"
    return f"{family or 'unknown'}-host"
