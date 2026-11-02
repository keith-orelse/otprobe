"""Application context: the wiring every service and engine receives (built in app.main)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.adapters.base import CredentialVault
from app.adapters.registry import AdapterRegistry
from app.core.config import Settings
from app.core.db import Database
from app.core.events import EventHub
from app.core.pacing import Pacer
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
    extras: dict[str, Any]
