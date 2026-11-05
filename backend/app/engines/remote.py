"""Helpers shared by the engines that act on a host over WinRM (precheck, deployment, removal, restart)."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from app.context import AppContext


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
