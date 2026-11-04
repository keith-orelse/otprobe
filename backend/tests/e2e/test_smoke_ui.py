"""Playwright smoke test of the main journey through the real console (Vite) against the real API, with the agent
runtime and telemetry simulator as separate processes. Run with:  pytest -m e2e"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest

from tests.conftest import LiveServer, free_port, spawn_agent_runtime, spawn_telemetry_sim

pytestmark = pytest.mark.e2e
FRONTEND = Path(__file__).resolve().parents[3] / "frontend"
PW = {"operator": "operator-demo", "approver": "approver-demo", "admin": "admin-demo"}


async def wait_http(url: str, timeout: float = 60) -> None:
    async with httpx.AsyncClient() as c:
        for _ in range(int(timeout * 4)):
            try:
                if (await c.get(url)).status_code < 500:
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.25)
    raise AssertionError(f"{url} did not come up")


async def test_main_journey(db_path, tmp_path):
    playwright = pytest.importorskip("playwright.async_api")
    if shutil.which("npx") is None:
        pytest.skip("npx not available")
    async with LiveServer(db_path, heartbeat_interval_sec=1.0, speed_factor=0.05) as srv:
        port = free_port()
        vite = subprocess.Popen(["npx", "vite", "--port", str(port), "--strictPort"], cwd=FRONTEND,
                                env={**os.environ, "OTPROBE_API": srv.url}, stdout=open(tmp_path / "vite.log", "w"),
                                stderr=subprocess.STDOUT)
        agent = spawn_agent_runtime(srv.url, tmp_path / "agent.log")
        tele = spawn_telemetry_sim(srv.url, tmp_path / "telemetry.log", interval=0.5)
        ui = f"http://localhost:{port}"
        try:
            await wait_http(f"{ui}/login")
            async with playwright.async_playwright() as p:
                try:
                    browser = await p.chromium.launch(channel="chrome", headless=True)
                except Exception:  # noqa: BLE001
                    browser = await p.chromium.launch(headless=True)
                page = await browser.new_page(viewport={"width": 1500, "height": 1000})
                errors: list[str] = []
                page.on("pageerror", lambda e: errors.append(str(e)))
                expect = playwright.expect

                async def login(user: str) -> None:
                    await page.goto(f"{ui}/login")
                    await page.evaluate("sessionStorage.clear()")
                    await page.goto(f"{ui}/login")
                    await page.get_by_label("Username").fill(user)
                    await page.get_by_label("Password").fill(PW[user])
                    await page.get_by_role("button", name="SIGN IN").click()
                    await page.wait_for_selector(".user-box")

                async def open_asset(ip: str) -> None:
                    await page.goto(f"{ui}/assets")
                    await page.get_by_text(ip, exact=True).click()
                    await page.wait_for_selector(".asset-head")

                await login("operator")
                await expect(page.locator(".sim-banner")).to_have_text(
                    "SIMULATED ENVIRONMENT - NO REAL DEVICES ARE BEING SCANNED")
                await page.goto(f"{ui}/discovery")
                await page.get_by_role("button", name="START DISCOVERY").click()
                await page.wait_for_selector(".panel-head >> text=COMPLETED", timeout=60000)

                await open_asset("192.168.20.13")
                await page.get_by_role("button", name="RUN AGENTLESS PROBE").click()
                await page.wait_for_selector("text=Windows Engineering Workstation", timeout=60000)
                await open_asset("192.168.10.10")
                await page.get_by_role("button", name="RUN AGENTLESS PROBE").click()
                await expect(page.locator(".reason").first).to_have_text(
                    "Traditional PLCs are handled agentless/read-only in this POC.", timeout=60000)
                await expect(page.get_by_role("button", name="DEPLOY AGENT")).to_be_disabled()

                await open_asset("192.168.20.13")
                await page.get_by_role("button", name="DEPLOY AGENT").click()
                await page.get_by_role("button", name="SUBMIT FOR APPROVAL").click()
                await page.wait_for_url("**/deployments/*")
                deployment = page.url
                await login("approver")
                await page.goto(f"{ui}/approvals")
                await page.locator("tr", has_text="eng-ws-01").get_by_role("button", name="Approve").click()
                await page.wait_for_selector("tr:has-text('eng-ws-01') >> text=approver")
                await login("operator")
                await page.goto(deployment)
                await page.get_by_role("button", name="RUN PRECHECK").click()
                await page.wait_for_selector("text=PRECHECK PASSED", timeout=60000)
                await page.get_by_role("button", name="DEPLOY AGENT").click()
                await page.wait_for_selector("h1 >> text=COMPLETED", timeout=90000)

                await open_asset("192.168.20.13")
                run = page.get_by_role("button", name="RUN DEEP ASSESSMENT")
                await expect(run).to_be_enabled(timeout=30000)
                await run.click()
                await expect(page.locator(".compliance")).to_contain_text("75", timeout=60000)
                await page.goto(f"{ui}/findings")
                await page.wait_for_selector("text=WIN-PATCH-001")
                await page.goto(f"{ui}/telemetry")
                await page.wait_for_selector("text=factory/line1/sensor01/temperature", timeout=30000)
                await page.goto(f"{ui}/audit")
                await page.wait_for_selector("text=hash chain valid")
                await page.screenshot(path=str(tmp_path / "smoke-end.png"))
                assert errors == [], errors
                await browser.close()
        finally:
            for proc in (agent, tele, vite):
                proc.terminate()
                proc.wait(10)
