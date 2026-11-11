"""Bundled MQTT broker, Mode A (docs/MQTT_BROKER.md), against a real Mosquitto that OTProbe starts itself, on
127.0.0.1 with the OTProbe TLS certificates. Devices are real MQTT clients (paho) and scripts/fake_sensor.py.

Proves: the broker starts locked down (TLS only, no anonymous access); accounts are admin-only, shown once, limited to
their own topics and never overlap; messages land on the right asset; rules fire on plain numbers and on silence; a
disabled, deleted or re-keyed account is disconnected at once; OTProbe's own client cannot publish; a crashed broker
is restarted."""

from __future__ import annotations

import asyncio
import inspect
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

import httpx
import paho.mqtt.client as paho
import pytest

from app.adapters.real.net import mosquitto as mq
from app.core.mqtt_topics import check_password
from app.main import create_app
from tests.conftest import free_port
from tests.live.conftest import LiveHarness, live_settings
from tests.live.test_go_agent_e2e import load_tls_helper
from tests.live.test_live_loopback import add_scope, safe_mode

pytestmark = [pytest.mark.live,
              pytest.mark.skipif(mq.find_binary() is None, reason="mosquitto not installed (brew/apt install "
                                                                    "mosquitto)")]
REPO = Path(__file__).resolve().parents[3]
TOPIC = "plant/line1/sensor01/temperature"


class Device:
    """A plant device: a real MQTT client on the broker's TLS listener."""

    def __init__(self, port: int, ca: Path | None, username: str | None, password: str | None,
                 client_id: str = "dev-sensor01") -> None:
        self.c = paho.Client(paho.CallbackAPIVersion.VERSION2, client_id=client_id, protocol=paho.MQTTv311)
        if username:
            self.c.username_pw_set(username, password)
        if ca:
            self.c.tls_set(ca_certs=str(ca))
        self.port = port
        self.reason = None
        self.done = threading.Event()
        self.c.on_connect = self._on_connect
        self.c.on_disconnect = lambda c, u, f, reason, p: self.done.set()

    def _on_connect(self, c, userdata, flags, reason, properties):
        self.reason = reason
        self.done.set()

    async def connect(self) -> bool:
        """True when the broker accepted the login."""
        def run():
            self.c.connect("127.0.0.1", self.port, keepalive=30)
            self.c.loop_start()
            self.done.wait(5)
            self.done.clear()
        await asyncio.to_thread(run)
        return self.reason is not None and not self.reason.is_failure and self.c.is_connected()

    async def publish(self, topic: str, payload: str) -> None:
        info = self.c.publish(topic, payload, qos=1)
        await asyncio.to_thread(info.wait_for_publish, 5)

    @property
    def connected(self) -> bool:
        return self.c.is_connected()

    def close(self) -> None:
        self.c.disconnect()
        self.c.loop_stop()


@pytest.fixture
async def site(tmp_path):
    """OTProbe with the bundled broker on, TLS from a lab CA, staleness windows scaled down (300 s -> 1.5 s)."""
    load_tls_helper().main(["127.0.0.1"], tmp_path / "tls")
    port = free_port()
    settings = live_settings(tmp_path / "mqtt.db", mqtt_broker="bundled", mqtt_port=port,
                             mqtt_dir=str(tmp_path / "mqtt"), tls_ca_file=str(tmp_path / "tls" / "otprobe-ca.pem"),
                             public_url="https://127.0.0.1:8000", telemetry_time_scale=0.005,
                             heartbeat_interval_sec=1.0)
    app = create_app(settings)
    devices: list[Device] = []
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            h = await LiveHarness(app, client).login("admin")
            h.port, h.ca, h.devices = port, tmp_path / "tls" / "otprobe-ca.pem", devices
            yield h
    for d in devices:
        d.close()


def device(h, username: str | None, password: str | None, client_id: str = "dev-sensor01",
           ca: bool = True) -> Device:
    d = Device(h.port, h.ca if ca else None, username, password, client_id)
    h.devices.append(d)
    return d


async def create(h, username="sensor01", prefix="plant/line1/sensor01", **extra) -> dict:
    await h.login("admin")
    r = await h.client.post("/api/v1/mqtt/accounts", json={"username": username, "topicPrefix": prefix, **extra})
    assert r.status_code == 201, r.text
    return r.json()


async def patch(h, username: str, body: dict) -> dict:
    await h.login("admin")
    r = await h.client.patch(f"/api/v1/mqtt/accounts/{username}", json=body)
    assert r.status_code == 200, r.text
    return r.json()


async def until(pred, timeout: float = 5.0):
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        value = pred()
        if inspect.isawaitable(value):
            value = await value
        if value:
            return value
        assert asyncio.get_running_loop().time() < deadline, "condition not met in time"
        await asyncio.sleep(0.05)


async def loopback_asset(h) -> str:
    await add_scope(h)
    await safe_mode(h, False)
    await h.post("/discovery/jobs", {"targets": ["127.0.0.1/32"], "methods": ["ICMP"]}, expect=202)
    await h.idle()
    return (await h.asset_by_ip("127.0.0.1"))["id"]


async def test_broker_starts_locked_down(site):
    h = site
    st = await h.get("/mqtt/broker")
    assert st["mode"] == "bundled" and st["running"], st["error"]
    assert st["version"].startswith("2.") and st["caAvailable"]
    assert st["listeners"] == [{"port": h.port, "tls": True, "bind": "all interfaces"}]
    assert {c["ruleId"]: c["status"] for c in st["checks"]} == {
        "MQTT-BRK-001": "PASS", "MQTT-BRK-002": "PASS", "MQTT-BRK-003": "PASS", "MQTT-BRK-004": "PASS"}
    assert not await device(h, None, None, "anon").connect()                 # no anonymous access
    assert not await device(h, "sensor01", "guess", "nobody").connect()      # unknown account
    assert not await device(h, "sensor01", "guess", "plain", ca=False).connect()   # TLS only on the device port
    r = await h.client.get("/api/v1/mqtt/ca.pem")
    assert r.status_code == 200 and r.text == h.ca.read_text()
    files = Path(h.ctx.broker.layout.root)
    assert all(oct((files / f).stat().st_mode)[-3:] == "600" for f in ("passwd", "acl", "server.key"))
    await h.login("operator")
    assert (await h.get("/mqtt/broker"))["log"] == []                         # the log is for admins


async def test_accounts_are_admin_only_shown_once_and_never_overlap(site):
    h = site
    await h.login("operator")
    r = await h.client.post("/api/v1/mqtt/accounts", json={"username": "sensor01", "topicPrefix": "plant/x"})
    assert r.status_code == 403
    made = await create(h)
    assert len(made["password"]) >= 20 and made["connection"] == {
        "host": "127.0.0.1", "port": h.port, "tls": True, "username": "sensor01",
        "topic": "plant/line1/sensor01/<metric>", "caCertificate": "/api/v1/mqtt/ca.pem"}
    listed = (await h.client.get("/api/v1/mqtt/accounts")).text
    assert made["password"] not in listed and "sensor01" in listed
    stored = Path(h.ctx.broker.layout.passwd).read_text()
    assert made["password"] not in stored and check_password(made["password"], stored.split("sensor01:")[1].strip())

    for prefix, status, slug in (("plant/#", 422, "mqtt-acl-too-broad"), ("#", 422, "mqtt-acl-too-broad"),
                                 ("$SYS/x", 422, "mqtt-acl-too-broad"), ("plant/line1", 409, "mqtt-prefix-overlap"),
                                 ("plant/line1/sensor01/temp", 409, "mqtt-prefix-overlap")):
        r = await h.client.post("/api/v1/mqtt/accounts", json={"username": "other1", "topicPrefix": prefix})
        assert (r.status_code, r.json()["type"].rsplit("/", 1)[-1]) == (status, slug), (prefix, r.text)
    r = await h.client.post("/api/v1/mqtt/accounts", json={"username": "otprobe-x", "topicPrefix": "plant/y"})
    assert r.status_code == 422
    r = await h.client.post("/api/v1/mqtt/accounts", json={"username": "sensor01", "topicPrefix": "plant/z"})
    assert r.status_code == 409
    actions = [e["action"] for e in (await h.get("/audit-events"))["items"]]
    assert "MQTT_ACCOUNT_CREATED" in actions


async def test_messages_reach_the_right_asset_and_rules_fire(site):
    h = site
    made = await create(h)
    dev = device(h, "sensor01", made["password"])
    assert await dev.connect()
    await dev.publish(TOPIC, "42.5")
    await dev.publish("plant/line1/sensor02/temperature", "99")             # not its topic: the broker drops it

    async def topics():
        return {t["topic"]: t for t in await h.get("/telemetry/topics")}
    by = await until(topics)
    assert list(by) == [TOPIC]
    assert by[TOPIC]["clientId"] == "sensor01" and by[TOPIC]["lastPayload"] == 42.5
    assert by[TOPIC]["assetId"] is None                                     # not linked yet, no asset at its address
    acc = (await h.get("/mqtt/accounts"))[0]
    assert acc["connected"] and acc["connections"][0]["ip"] == "127.0.0.1" and acc["topics"] == [TOPIC]

    asset_id = await loopback_asset(h)
    linked = await patch(h, "sensor01", {"assetId": asset_id})
    assert linked["assetName"] and (await topics())[TOPIC]["assetId"] == asset_id   # earlier messages moved too

    await dev.publish(TOPIC, "97")
    found = await h.wait_for("/findings", lambda d: any(f["ruleId"] == "TEL-TEMP-002" for f in d["items"]), 5)
    crit = next(f for f in found["items"] if f["ruleId"] == "TEL-TEMP-002")
    assert crit["severity"] == "CRITICAL" and crit["assetId"] == asset_id and crit["observed"] == 97
    events = (await h.get("/audit-events", params={"action": "TELEMETRY_THRESHOLD_EXCEEDED"}))["items"]
    assert any(f"(sensor01) reported 97 on {TOPIC}" in e["details"]["message"] for e in events)
    await dev.publish(TOPIC, "40")
    await h.wait_for("/findings", lambda d: all(f["status"] == "RESOLVED" for f in d["items"]
                                                if f["ruleId"].startswith("TEL-TEMP")), 5)

    await h.login("operator")
    r = await h.post(f"/assets/{asset_id}/probes", expect=202)
    await h.idle()
    step = next(s for s in (await h.get(f"/probes/{r.json()['id']}"))["steps"] if s["name"] == "MQTT")
    assert step["status"] == "OK" and "dev-sensor01" in step["detail"], step


async def test_silent_device_raises_a_finding_that_clears_when_it_talks_again(site):
    h = site
    asset_id = await loopback_asset(h)
    made = await create(h, assetId=asset_id)
    dev = device(h, "sensor01", made["password"])
    assert await dev.connect()
    await dev.publish(TOPIC, "41")
    found = await h.wait_for("/findings", lambda d: any(f["ruleId"] == "TEL-STALE-001" and f["status"] == "OPEN"
                                                        for f in d["items"]), 10)
    stale = next(f for f in found["items"] if f["ruleId"] == "TEL-STALE-001")
    assert stale["assetId"] == asset_id and str(stale["observed"]).startswith("no message for")
    assert not any(f["ruleId"] == "TEL-PLC-001" for f in found["items"])   # a temperature topic says nothing of PLCs
    await dev.publish(TOPIC, "41")
    assert (await h.get(f"/findings/{stale['id']}"))["status"] == "RESOLVED"


async def test_disabled_rekeyed_or_deleted_accounts_are_disconnected_at_once(site):
    h = site
    made = await create(h)
    dev = device(h, "sensor01", made["password"])
    assert await dev.connect()

    await patch(h, "sensor01", {"enabled": False})
    await until(lambda: not dev.connected)
    assert not await device(h, "sensor01", made["password"], "again").connect()
    refused = (await h.get("/mqtt/broker"))["refused"]
    assert refused and refused[-1]["clientId"] == "again" and refused[-1]["ip"] == "127.0.0.1"
    await patch(h, "sensor01", {"enabled": True})
    dev = device(h, "sensor01", made["password"])
    assert await dev.connect()

    r = await h.client.post("/api/v1/mqtt/accounts/sensor01/password")
    assert r.status_code == 200, r.text
    new = r.json()["password"]
    await until(lambda: not dev.connected)
    assert not await device(h, "sensor01", made["password"], "old-pass").connect()
    fresh = device(h, "sensor01", new, "new-pass")
    assert await fresh.connect()

    assert (await h.client.delete("/api/v1/mqtt/accounts/sensor01")).status_code == 204
    await until(lambda: not fresh.connected)
    assert not await device(h, "sensor01", new, "after-delete").connect()
    actions = {e["action"] for e in (await h.get("/audit-events"))["items"]}
    assert {"MQTT_ACCOUNT_DISABLED", "MQTT_ACCOUNT_ENABLED", "MQTT_ACCOUNT_PASSWORD_ROTATED",
            "MQTT_ACCOUNT_DELETED"} <= actions


async def test_otprobe_cannot_publish_and_a_crashed_broker_comes_back(site):
    h = site
    broker = h.ctx.broker
    made = await create(h)
    # OTProbe's own account may read, never publish (the ACL), so it cannot send anything to a device.
    spy = paho.Client(paho.CallbackAPIVersion.VERSION2, client_id="otprobe-spy")
    spy.username_pw_set(mq.READER, broker._reader_password)
    spy.connect("127.0.0.1", broker._internal_port)
    spy.loop_start()
    spy.publish(TOPIC, "13").wait_for_publish(5)
    await asyncio.sleep(0.5)
    spy.disconnect()
    spy.loop_stop()
    assert await h.get("/telemetry/topics") == []
    assert "topic read #" in Path(broker.layout.acl).read_text() and "topic write" not in \
        Path(broker.layout.acl).read_text().split("user sensor01")[0]

    os.kill(broker.proc.pid, signal.SIGKILL)
    await until(lambda: broker.restarts == 1 and broker.running, timeout=15)
    dev = device(h, "sensor01", made["password"])
    assert await dev.connect()                                              # accounts survive the restart
    await dev.publish(TOPIC, "44")
    await until(lambda: h.get("/telemetry/topics"))


async def test_fake_sensor_script(site):
    h = site
    made = await create(h)
    base = [sys.executable, str(REPO / "scripts" / "fake_sensor.py"), "--port", str(h.port), "--ca", str(h.ca),
            "--username", "sensor01", "--topic", TOPIC, "--count", "3", "--interval", "0.05"]
    ok = await asyncio.to_thread(subprocess.run, base + ["--password", made["password"], "--json"],
                                 capture_output=True, text=True, timeout=30)
    assert ok.returncode == 0, ok.stderr
    assert ok.stdout.count(TOPIC) == 3
    topic = (await until(lambda: h.get("/telemetry/topics")))[0]
    await until(lambda: _messages(h, 3))
    assert set(topic["lastPayload"]) == {"temperature", "unit"}
    bad = await asyncio.to_thread(subprocess.run, base + ["--password", "wrong-password"], capture_output=True,
                                  text=True, timeout=30)
    assert bad.returncode == 3 and "login refused" in bad.stderr


async def _messages(h, n: int) -> bool:
    return len(await h.get("/telemetry/messages")) >= n


async def test_broker_off_by_default(live):
    st = await live.get("/mqtt/broker")
    assert st == {**st, "mode": "off", "running": False}
    await live.login("admin")
    r = await live.client.post("/api/v1/mqtt/accounts", json={"username": "sensor01", "topicPrefix": "plant/x"})
    assert r.status_code == 409 and r.json()["type"].endswith("mqtt-broker-off")
