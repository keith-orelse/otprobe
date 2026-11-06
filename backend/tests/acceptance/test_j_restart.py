"""J (Phase 2 part): restart preserves inventory, history and simulated state; interrupted work is failed."""

import httpx
import pytest

from app.core.audit import system
from app.main import create_app
from app.models import DiscoveryJob
from app.workflow.machine import DISCOVERY
from tests.conftest import Harness, make_settings
from tests.sim import SimEnvironment

pytestmark = pytest.mark.acceptance


async def test_restart_preserves_state(db_path):
    app = create_app(make_settings(db_path), environment=SimEnvironment())
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            h = await Harness(app, c).login()
            await h.discover()
            probe = await h.probe("192.168.20.13")
            app.state.ctx.extras["world"].update_state(
                "dev-ews01", lambda st: st["firewall"].update(state="disabled"))
            with app.state.ctx.db.session() as s:   # leave a job mid-flight, as a crash would
                job = DiscoveryJob(targets=["192.168.20.0/24"], methods=["ARP"], requested_by="t", correlation_id="c")
                DISCOVERY.create(s, job, system("test"))
                DISCOVERY.transition(s, job, "RUNNING", system("test"))
                stuck = job.id
            assets_before = await h.assets()
            audit_before = (await h.get("/audit-events"))["total"]

    app2 = create_app(make_settings(db_path), environment=SimEnvironment())
    async with app2.router.lifespan_context(app2):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app2), base_url="http://t") as c:
            h = await Harness(app2, c).login()
            assert await h.assets() == assets_before
            assert (await h.get(f"/probes/{probe['id']}"))["status"] == "COMPLETED"
            job = await h.get(f"/discovery/jobs/{stuck}")
            assert job["status"] == "FAILED" and job["error"] == "Interrupted by server restart"
            assert (await h.get("/audit-events"))["total"] > audit_before
            assert (await h.get("/audit-events/verify"))["valid"] is True
            dev = app2.state.ctx.extras["world"].device("dev-ews01")
            assert dev.state["firewall"]["state"] == "disabled"   # simulated world not re-seeded over
