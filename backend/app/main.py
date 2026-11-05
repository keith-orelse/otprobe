"""Composition root: the only module that chooses real or simulated adapters and wires them into the app.

ADAPTER_MODE=real (default): live network. Real adapters behind the network gate; no simulator is loaded, no demo
data or demo passwords are seeded. ADAPTER_MODE=simulated: the POC world, used by the test suite until the
simulator moves to tests (phase L6)."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from typing import Callable, Iterable

from fastapi import FastAPI
from sqlalchemy import select

from app.adapters.base import Protocol
from app.adapters.registry import AdapterRegistry, parse_overrides
from app.adapters.vault import LocalCredentialVault
from app.api.v1 import router as api_v1
from app.context import AppContext
from app.core import audit, events
from app.core.config import Settings
from app.core.correlation import CorrelationMiddleware
from app.core.crypto import fernet_for, live_vault_key
from app.core.db import Database
from app.core.errors import install_problem_handlers
from app.core.events import EventHub
from app.core.migrations import upgrade
from app.core.pacing import Pacer
from app.core.security import StreamTickets
from app.models import AgentBuild
from app.rules.book import RuleBook
from app.services import agent_builds, safety
from app.services.agents import run_watchdog
from app.services.assessments import sync_policies
from app.services.bootstrap import seed_config, seed_live_users, seed_trust
from app.services.telemetry import TelemetryService
from app.workflow.recovery import recover_interrupted
from app.workflow.runner import JobRunner

SIMULATION_BANNER = "SIMULATED ENVIRONMENT - NO REAL DEVICES ARE BEING SCANNED"
LIVE_BANNER = "LIVE NETWORK - only addresses inside the configured scan scope are contacted"
DEMO_JWT_SECRET = "change-me-demo-jwt-secret-at-least-32-bytes"
AdapterPlugin = Callable[[AdapterRegistry, AppContext], None]
log = logging.getLogger("otprobe")


def _simulated_parts(settings: Settings, db: Database, fernet, registry: AdapterRegistry, pacer: Pacer) -> dict:
    # Imported here so live mode never loads the simulator.
    from app.adapters.simulated import SimulatedControl, build_transfer, register_simulated
    from app.sim.broker import Broker
    from app.sim.latency import SimLatency
    from app.sim.seed import seed_world
    from app.sim.world import SimWorld

    with db.session() as s:
        seed_world(s)
        seed_config(s, fernet)
        seed_trust(s)
    world, broker = SimWorld(db), Broker()
    latency = SimLatency(settings.seed, pacer)
    register_simulated(registry, world, latency, broker)
    return {"transfer": build_transfer(registry, world, latency), "sim_control": SimulatedControl(world, broker),
            "gate": None, "extras": {"world": world, "broker": broker}}


def _live_parts(settings: Settings, db: Database, registry: AdapterRegistry) -> dict:
    from app.adapters.real import NetworkGate, register_real
    from app.adapters.real.winrm import RealPackageTransfer

    with db.session() as s:
        for username, password in seed_live_users(s, settings):
            log.warning("created account %r with generated password %r - change it after first login",
                        username, password)
    gate = NetworkGate(max_pps=settings.scan_max_pps)
    register_real(registry, gate)

    def resolve_build(package_id: str) -> str | None:
        """Local file of the verified agent build behind a package id (agent-<version>-<build id>)."""
        with db.session() as s:
            for b in s.scalars(select(AgentBuild)):
                if agent_builds.package_id(b.version, b.build_id) == package_id:
                    return b.path
        return None

    transfer = RealPackageTransfer(lambda: registry.get(Protocol.WINRM), resolve_build)
    return {"transfer": transfer, "sim_control": None, "gate": gate, "extras": {}}


def build_context(settings: Settings, plugins: Iterable[AdapterPlugin] = ()) -> AppContext:
    if settings.run_migrations:
        upgrade(settings.database_url)
    if settings.live:
        settings = replace(settings, vault_key=live_vault_key(settings.vault_key, settings.vault_key_file,
                                                              settings.database_url))
        if settings.jwt_secret == DEMO_JWT_SECRET:
            settings = replace(settings, jwt_secret=live_vault_key("", _sibling(settings.vault_key_file, "jwt"),
                                                                   settings.database_url, "jwt"))
    db = Database(settings.database_url)
    hub = EventHub()
    events.install(db.sessionmaker, hub)
    fernet = fernet_for(settings.vault_key)
    pacer = Pacer(settings.speed_factor)
    registry = AdapterRegistry(settings.adapter_mode, parse_overrides(settings.adapter_overrides))
    parts = _live_parts(settings, db, registry) if settings.live else _simulated_parts(settings, db, fernet,
                                                                                         registry, pacer)
    ctx = AppContext(settings=settings, db=db, hub=hub, registry=registry, vault=LocalCredentialVault(db, fernet),
                     runner=JobRunner(), pacer=pacer, rules=RuleBook.load(settings.rules_dir),
                     transfer=parts["transfer"], sim_control=parts["sim_control"], tickets=StreamTickets(),
                     extras=parts["extras"], gate=parts["gate"])
    for plugin in plugins:
        plugin(registry, ctx)
    with db.session() as s:
        sync_policies(s, ctx.rules)
        safety.push_to_gate(ctx, s)
        if settings.live:
            agent_builds.rescan(ctx, s, audit.system("agent-builds"))
    registry.validate()   # fails fast when a required protocol has no adapter in the selected mode
    interrupted = recover_interrupted(db)
    if interrupted:
        log.warning("marked %d interrupted workflow(s) as failed", interrupted)
    return ctx


def _sibling(key_file: str, name: str) -> str:
    """The JWT key lives next to the vault key (or next to the DB when no key file is configured)."""
    return str(Path(key_file).with_name(f"otprobe-{name}.key")) if key_file else ""


def create_app(settings: Settings | None = None, adapter_plugins: Iterable[AdapterPlugin] = ()) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        ctx = build_context(settings, adapter_plugins)
        app.state.ctx = ctx
        telemetry = ctx.extras["telemetry"] = TelemetryService(ctx)
        await telemetry.start()
        watchdog = asyncio.create_task(run_watchdog(ctx), name="heartbeat-watchdog")
        try:
            yield
        finally:
            watchdog.cancel()
            await asyncio.gather(watchdog, return_exceptions=True)
            await telemetry.stop()
            await ctx.runner.shutdown()
            ctx.db.dispose()

    banner = LIVE_BANNER if settings.live else SIMULATION_BANNER
    app = FastAPI(title="OTProbe API", version="0.3.0", description=f"**{banner}**",
                  docs_url="/docs", openapi_url="/openapi.json", lifespan=lifespan)
    app.add_middleware(CorrelationMiddleware, environment="LIVE" if settings.live else "SIMULATED")
    install_problem_handlers(app)
    app.include_router(api_v1)
    if not settings.live:
        from app.api.sim.routes import router as sim_router
        app.include_router(sim_router)
    return app


app = create_app()
