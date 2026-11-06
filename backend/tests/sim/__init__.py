"""The simulated OT network (formerly app.sim, moved here in phase L6). The product never imports this package;
the test suite plugs it in with ``create_app(settings, environment=SimEnvironment())`` and ADAPTER_MODE=simulated."""

from __future__ import annotations

from typing import Any

from app.adapters.registry import AdapterRegistry
from app.core.config import Settings
from app.core.db import Database
from app.core.pacing import Pacer


class SimEnvironment:
    """The simulated world, its adapters and the simulator-only routes (/sim/v1 and /api/v1/demo)."""

    def __init__(self) -> None:
        from tests.sim.demo_routes import router as demo_router
        from tests.sim.routes import router as sim_router
        self.routers = [sim_router, demo_router]

    def build(self, settings: Settings, db: Database, fernet: Any, registry: AdapterRegistry, pacer: Pacer) -> dict:
        from tests.sim.adapters import SimulatedControl, build_transfer, register_simulated
        from tests.sim.broker import Broker
        from tests.sim.latency import SimLatency
        from tests.sim.models import SimBase
        from tests.sim.seed import seed_config, seed_trust, seed_world
        from tests.sim.world import SimWorld

        SimBase.metadata.create_all(db.engine)
        with db.session() as s:
            seed_world(s)
            seed_config(s, fernet)
            seed_trust(s)
        world, broker = SimWorld(db), Broker()
        latency = SimLatency(settings.seed, pacer)
        register_simulated(registry, world, latency, broker)
        return {"transfer": build_transfer(registry, world, latency), "gate": None,
                "extras": {"world": world, "broker": broker, "sim_control": SimulatedControl(world, broker)}}
