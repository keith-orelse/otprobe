"""Composition root: the only module that wires simulated adapters and the simulated world into the app."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Callable, Iterable

from fastapi import FastAPI

from app.adapters.registry import AdapterRegistry, parse_overrides
from app.adapters.simulated import SimulatedControl, SimulatedCredentialVault, build_transfer, register_simulated
from app.api.sim.routes import router as sim_router
from app.api.v1 import router as api_v1
from app.context import AppContext
from app.core import events
from app.core.config import Settings
from app.core.correlation import CorrelationMiddleware
from app.core.crypto import fernet_for
from app.core.db import Database
from app.core.errors import install_problem_handlers
from app.core.events import EventHub
from app.core.migrations import upgrade
from app.core.pacing import Pacer
from app.core.security import StreamTickets
from app.rules.book import RuleBook
from app.services.agents import run_watchdog
from app.services.bootstrap import seed_config, seed_trust
from app.sim.broker import Broker
from app.sim.latency import SimLatency
from app.sim.seed import seed_world
from app.sim.world import SimWorld
from app.workflow.recovery import recover_interrupted
from app.workflow.runner import JobRunner

SIMULATION_BANNER = "SIMULATED ENVIRONMENT - NO REAL DEVICES ARE BEING SCANNED"
AdapterPlugin = Callable[[AdapterRegistry, AppContext], None]
log = logging.getLogger("otprobe")


def build_context(settings: Settings, plugins: Iterable[AdapterPlugin] = ()) -> AppContext:
    if settings.run_migrations:
        upgrade(settings.database_url)
    db = Database(settings.database_url)
    hub = EventHub()
    events.install(db.sessionmaker, hub)
    fernet = fernet_for(settings.vault_key)
    with db.session() as s:
        seed_world(s)
        seed_config(s, fernet)
        seed_trust(s)
    pacer = Pacer(settings.speed_factor)
    world, broker = SimWorld(db), Broker()
    registry = AdapterRegistry(settings.adapter_mode, parse_overrides(settings.adapter_overrides))
    latency = SimLatency(settings.seed, pacer)
    register_simulated(registry, world, latency, broker)
    ctx = AppContext(settings=settings, db=db, hub=hub, registry=registry,
                     vault=SimulatedCredentialVault(db, fernet), runner=JobRunner(), pacer=pacer,
                     rules=RuleBook.load(settings.rules_dir), transfer=build_transfer(registry, world, latency),
                     sim_control=SimulatedControl(world), tickets=StreamTickets(),
                     extras={"world": world, "broker": broker})
    for plugin in plugins:
        plugin(registry, ctx)
    registry.validate()   # fails fast, e.g. ADAPTER_MODE=real with no real adapters registered
    interrupted = recover_interrupted(db)
    if interrupted:
        log.warning("marked %d interrupted workflow(s) as failed", interrupted)
    return ctx


def create_app(settings: Settings | None = None, adapter_plugins: Iterable[AdapterPlugin] = ()) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        ctx = build_context(settings, adapter_plugins)
        app.state.ctx = ctx
        watchdog = asyncio.create_task(run_watchdog(ctx), name="heartbeat-watchdog")
        try:
            yield
        finally:
            watchdog.cancel()
            await asyncio.gather(watchdog, return_exceptions=True)
            await ctx.runner.shutdown()
            ctx.db.dispose()

    app = FastAPI(title="OTProbe API", version="0.2.0", description=f"**{SIMULATION_BANNER}**",
                  docs_url="/docs", openapi_url="/openapi.json", lifespan=lifespan)
    app.add_middleware(CorrelationMiddleware)
    install_problem_handlers(app)
    app.include_router(api_v1)
    app.include_router(sim_router)
    return app


app = create_app()
