"""Simulated Probe Agent runtime.

Runs as its own process (container `agent-runtime`). It represents the agent service on every virtual host where
the deployment engine installed it. All communication with OTProbe is OUTBOUND HTTP initiated here:
enroll -> heartbeat -> long-poll tasks. The server never connects to this process.

Reading the host's own disk/registry is simulated through the /sim/v1 API (X-Sim-Token).
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
from datetime import datetime, timezone

import httpx

from otprobe_agent.collectors import collect

log = logging.getLogger("otprobe.agent")


class Config:
    def __init__(self) -> None:
        self.api_url = os.environ.get("OTPROBE_API_URL", "http://127.0.0.1:8000").rstrip("/")
        self.sim_token = os.environ.get("SIM_SERVICE_TOKEN", "change-me-sim-token")
        self.discovery_poll_sec = float(os.environ.get("RUNTIME_POLL_SEC", "2"))
        self.max_task_wait_sec = int(os.environ.get("TASK_POLL_WAIT_SEC", "20"))


class Revoked(Exception):
    """Credential revoked or enrollment rejected: stays stopped until the agent is reinstalled."""


class Crashed(Exception):
    """Simulated process crash: stays stopped until the service is restarted (fault cleared)."""


class Agent:
    """One agent instance = the OTProbeAgent service on one virtual host."""

    def __init__(self, cfg: Config, client: httpx.AsyncClient, device_id: str) -> None:
        self.cfg, self.client, self.device_id = cfg, client, device_id
        self.agent_id: str | None = None
        self.credential: str | None = None
        self.interval = 10.0
        self.seq = 0
        self.task_wait = cfg.max_task_wait_sec

    @property
    def sim(self) -> dict[str, str]:
        return {"X-Sim-Token": self.cfg.sim_token}

    @property
    def auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.credential}"}

    async def local_state(self) -> dict:
        r = await self.client.get(f"{self.cfg.api_url}/sim/v1/hosts/{self.device_id}/local-state", headers=self.sim)
        r.raise_for_status()
        return r.json()

    async def run(self) -> None:
        state = await self.local_state()
        ident = state.get("identity") or {}
        if ident.get("credential"):
            self.agent_id, self.credential = ident["agentId"], ident["credential"]
            log.info("[%s] resuming as agent %s", self.device_id, self.agent_id[:8])
        else:
            await self.enroll(state)
        await asyncio.gather(self.heartbeat_loop(), self.task_loop())

    async def enroll(self, state: dict) -> None:
        r = await self.client.get(f"{self.cfg.api_url}/sim/v1/hosts/{self.device_id}/install-bundle", headers=self.sim)
        r.raise_for_status()
        bundle = r.json()
        token = bundle["enrollmentToken"]
        if "enrollment_failure" in state.get("faults", []):
            token = token[:-6] + "XXXXXX"   # simulated: bundle corrupted / token tampered
        body = {"enrollmentToken": token, "hostname": bundle["hostname"],
                "hostFingerprint": bundle["hostFingerprint"], "agentVersion": bundle["agentVersion"]}
        r = await self.client.post(f"{self.cfg.api_url}/api/v1/agents/enroll", json=body)
        if r.status_code != 201:
            raise Revoked(f"enrollment rejected: {r.status_code} {r.text[:200]}")
        data = r.json()
        self.agent_id, self.credential = data["agentId"], data["agentCredential"]
        self.interval, self.task_wait = data["heartbeatIntervalSec"], min(data["taskPollWaitSec"], self.task_wait)
        await self.client.put(f"{self.cfg.api_url}/sim/v1/hosts/{self.device_id}/agent-identity", headers=self.sim,
                              json={"agentId": self.agent_id, "credential": self.credential})
        log.info("[%s] enrolled as agent %s", self.device_id, self.agent_id[:8])

    def _check(self, r: httpx.Response) -> None:
        if r.status_code == 401:
            raise Revoked(r.json().get("detail", "credential rejected"))

    async def heartbeat_loop(self) -> None:
        while True:
            state = await self.local_state()
            faults = state.get("faults", [])
            if "agent_crashed" in faults:
                raise Crashed("process crashed (simulated)")
            if state.get("online") and "heartbeat_blocked" not in faults:
                self.seq += 1
                hb = {"seq": self.seq, "agentTime": datetime.now(timezone.utc).isoformat(),
                      "agentVersion": "1.1.0", "cpuPct": 2.5, "memMb": 46.0, "queueDepth": 0}
                try:
                    r = await self.client.post(f"{self.cfg.api_url}/api/v1/agents/{self.agent_id}/heartbeat",
                                               json=hb, headers=self.auth)
                    self._check(r)
                except httpx.TransportError as exc:
                    log.warning("[%s] heartbeat failed: %s", self.device_id, exc)
            await asyncio.sleep(self.interval)

    async def task_loop(self) -> None:
        while True:
            state = await self.local_state()
            if not state.get("online") or "heartbeat_blocked" in state.get("faults", []):
                await asyncio.sleep(self.interval)
                continue
            try:
                r = await self.client.get(f"{self.cfg.api_url}/api/v1/agents/{self.agent_id}/tasks",
                                          params={"waitSec": self.task_wait}, headers=self.auth,
                                          timeout=self.task_wait + 10)
                self._check(r)
                for task in r.json() if r.status_code == 200 else []:
                    await self.handle(task)
            except httpx.TransportError:
                await asyncio.sleep(self.interval)


    async def handle(self, task: dict) -> None:
        log.info("[%s] task %s %s", self.device_id, task["taskId"][:8], task["kind"])
        if task["kind"] != "RUN_ASSESSMENT":
            return
        r = await self.client.get(f"{self.cfg.api_url}/sim/v1/hosts/{self.device_id}/os-state", headers=self.sim)
        r.raise_for_status()
        host = r.json()
        if "assessment_timeout" in host["faults"]:
            log.warning("[%s] assessment hangs (simulated): evidence never uploaded", self.device_id)
            return
        evidence = collect(host["state"], task["payload"]["collectors"])
        r = await self.client.post(f"{self.cfg.api_url}/api/v1/agents/{self.agent_id}/tasks/{task['taskId']}/evidence",
                                   json=evidence, headers={**self.auth, "X-Correlation-ID": task["correlationId"]})
        self._check(r)
        log.info("[%s] evidence uploaded: %s", self.device_id, r.json() if r.status_code == 202 else r.text[:200])


class Supervisor:
    """Starts an Agent for every host whose OTProbeAgent service is running; stops it otherwise."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.running: dict[str, asyncio.Task] = {}
        self.dead: dict[str, str] = {}   # device -> "revoked" | "crashed"

    async def run(self) -> None:
        async with httpx.AsyncClient(timeout=30) as client:
            log.info("agent-runtime polling %s (host=%s)", self.cfg.api_url, platform.node())
            while True:
                try:
                    r = await client.get(f"{self.cfg.api_url}/sim/v1/hosts/agent-installs",
                                         headers={"X-Sim-Token": self.cfg.sim_token})
                    r.raise_for_status()
                    self.reconcile(client, r.json())
                except httpx.HTTPError as exc:
                    log.warning("cannot reach OTProbe: %s", exc)
                await asyncio.sleep(self.cfg.discovery_poll_sec)

    def reconcile(self, client: httpx.AsyncClient, installs: list[dict]) -> None:
        present = {i["deviceId"]: i for i in installs}
        for device_id, why in list(self.dead.items()):
            gone = device_id not in present
            restarted = why == "crashed" and "agent_crashed" not in present.get(device_id, {}).get("faults", [])
            if gone or restarted:
                del self.dead[device_id]
        wanted = {d for d, i in present.items()
                  if i["serviceState"] == "running" and "agent_crashed" not in i["faults"]} - set(self.dead)
        for device_id in wanted - set(self.running):
            agent = Agent(self.cfg, client, device_id)
            task = asyncio.create_task(agent.run(), name=f"agent:{device_id}")
            task.add_done_callback(lambda t, d=device_id: self._finished(d, t))
            self.running[device_id] = task
            log.info("[%s] agent service started", device_id)
        for device_id in set(self.running) - wanted:
            self.running.pop(device_id).cancel()
            log.info("[%s] agent service stopped", device_id)

    def _finished(self, device_id: str, task: asyncio.Task) -> None:
        self.running.pop(device_id, None)
        if task.cancelled():
            return
        exc = task.exception()
        if isinstance(exc, (Revoked, Crashed)):
            log.warning("[%s] agent stopped: %s", device_id, exc)
            self.dead[device_id] = "crashed" if isinstance(exc, Crashed) else "revoked"
        elif exc is not None:
            log.error("[%s] agent crashed unexpectedly: %r", device_id, exc)


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(name)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    asyncio.run(Supervisor(Config()).run())
