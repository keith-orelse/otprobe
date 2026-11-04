"""Application context: the wiring every service and engine receives (built in app.main)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from app.adapters.base import CredentialVault, PackageTransfer, SimulationControl
from app.adapters.registry import AdapterRegistry
from app.core.config import Settings
from app.core.db import Database
from app.core.events import EventHub
from app.core.pacing import Pacer
from app.core.security import StreamTickets
from app.rules.book import RuleBook
from app.workflow.runner import JobRunner


@dataclass
class AppContext:
    settings: Settings
    db: Database
    hub: EventHub
    registry: AdapterRegistry
    vault: CredentialVault
    runner: JobRunner
    pacer: Pacer
    rules: RuleBook
    transfer: PackageTransfer
    sim_control: SimulationControl | None
    tickets: StreamTickets
    extras: dict[str, Any]
    task_signals: dict[str, asyncio.Event] = field(default_factory=dict)

    def signal(self, agent_id: str) -> asyncio.Event:
        return self.task_signals.setdefault(agent_id, asyncio.Event())
