from __future__ import annotations

from dataclasses import dataclass

from app.core.audit import Actor

PERMISSIONS = {
    "OPERATOR": ["discovery.start", "probe.start", "deployment.request", "deployment.operate"],
    "APPROVER": ["approval.decide"],
    "ADMIN": ["discovery.start", "probe.start", "deployment.request", "deployment.operate", "approval.decide"],
}


@dataclass(frozen=True)
class CurrentUser:
    id: str
    username: str
    display_name: str
    role: str

    @property
    def actor(self) -> Actor:
        return Actor("USER", self.username, self.id)

    @property
    def permissions(self) -> list[str]:
        return PERMISSIONS.get(self.role, [])


@dataclass(frozen=True)
class CurrentAgent:
    id: str
    asset_id: str

    @property
    def actor(self) -> Actor:
        return Actor("AGENT", f"agent:{self.id[:8]}", self.id)
