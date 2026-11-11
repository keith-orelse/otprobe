"""The bundled Mosquitto broker as a child process of OTProbe (Mode A, docs/MQTT_BROKER.md, DECISIONS L6-10).

``BundledBroker`` writes the broker's files, restarts it if it dies, reloads it (SIGHUP) when device accounts change,
and learns which device connected from which address from the broker's log. OTProbe's own client ``otprobe-reader``
connects on a 127.0.0.1-only listener, may read every topic and may publish nothing (the broker's ACL file).

Devices connect in; OTProbe never connects out to a device over MQTT, so nothing here goes through the network gate.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import os
import secrets
import shutil
import signal
import socket
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Sequence

import paho.mqtt.client as paho

from app.adapters.base import BrokerAccount, MqttBroker
from app.adapters.real.net import mosquitto as mq
from app.core.clock import utcnow

log = logging.getLogger("otprobe.mqtt")
RESTART_DELAYS = (2, 5, 10, 30)
CHECK_CLIENT = "otprobe-check-"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class BundledBroker(MqttBroker):
    def __init__(self, root: str, binary: str = "", tls_port: int = 8883, plain_port: int = 0, bind: str = "",
                 cert_file: str = "", key_file: str = "", ca_file: str = "", public_host: str = "") -> None:
        self.layout = mq.Layout(Path(root))
        self.binary_setting = binary
        self.tls_port, self.plain_port, self.bind = tls_port, plain_port, bind
        self.cert_file, self.key_file, self.ca_file = cert_file, key_file, ca_file
        self.public_host = public_host
        self.accounts: list[BrokerAccount] = []
        self.on_message: Callable[[str, bytes, bool], None] | None = None
        self.proc: asyncio.subprocess.Process | None = None
        self.binary: str | None = None
        self.version = ""
        self.error = ""
        self.tls = False
        self.started_at: datetime | None = None
        self.restarts = 0
        self.anonymous_refused: bool | None = None
        self.log_tail: collections.deque[str] = collections.deque(maxlen=200)
        self.refused: collections.deque[dict[str, Any]] = collections.deque(maxlen=20)
        self.last_seen: dict[str, dict[str, Any]] = {}
        self._conns: dict[str, dict[str, Any]] = {}
        self._reader: paho.Client | None = None
        self._reader_password = ""
        self._internal_port = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ready: asyncio.Event | None = None
        self._reloaded: asyncio.Event | None = None
        self._apply_lock = asyncio.Lock()
        self._tasks: list[asyncio.Task] = []
        self._stopping = False

    # ---- lifecycle ---------------------------------------------------------------------------------------------

    async def start(self, accounts: Sequence[BrokerAccount]) -> None:
        self.accounts = list(accounts)
        self._loop = asyncio.get_running_loop()
        self._stopping = False
        self.binary = mq.find_binary(self.binary_setting)
        if self.binary is None:
            self.error = ("Mosquitto is not installed (apt install mosquitto / brew install mosquitto), or set "
                          "MQTT_BINARY to its path")
            log.error("MQTT broker not started: %s", self.error)
            return
        await self._launch()
        self._tasks.append(asyncio.create_task(self._supervise(), name="mqtt-broker-supervisor"))

    async def stop(self) -> None:
        self._stopping = True
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        self._stop_reader()
        await self._terminate()

    async def apply(self, accounts: Sequence[BrokerAccount], kick: Sequence[str] = ()) -> None:
        """Rewrite the account files and reload. Usernames in ``kick`` (a new password) are first removed and the
        broker reloaded, which disconnects them, then written back with the new password."""
        async with self._apply_lock:            # one change at a time; the last one wins
            self.accounts = list(accounts)
            if not self.running:
                return
            if kick:
                self._write_accounts([a for a in self.accounts if a.username not in kick])
                await self._reload()
                await self._wait_gone(kick)
            self._write_accounts(self.accounts)
            await self._reload()

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.returncode is None

    async def _launch(self) -> bool:
        self.error = ""
        self._conns.clear()
        layout = self.layout
        layout.root.mkdir(parents=True, exist_ok=True)
        os.chmod(layout.root, 0o700)
        layout.data.mkdir(exist_ok=True)
        self.tls = self._copy_tls()
        self._internal_port = free_port()
        self._reader_password = secrets.token_urlsafe(24)
        self._write_accounts(self.accounts)
        listeners = mq.Listeners(self._internal_port, self.tls_port, self.plain_port, self.bind)
        mq.write_private(layout.config, mq.render_config(layout, listeners, self.tls))
        self._hand_to_broker_user()
        self._ready = asyncio.Event()
        try:
            self.proc = await asyncio.create_subprocess_exec(
                self.binary, "-c", str(layout.config), stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT, stdin=asyncio.subprocess.DEVNULL)
        except OSError as exc:
            self.error = f"could not start {self.binary}: {exc}"
            return False
        self._tasks.append(asyncio.create_task(self._read_log(self.proc), name="mqtt-broker-log"))
        waiter = asyncio.create_task(self._ready.wait())
        exited = asyncio.create_task(self.proc.wait())
        await asyncio.wait({waiter, exited}, timeout=10, return_when=asyncio.FIRST_COMPLETED)
        waiter.cancel()
        exited.cancel()
        if not self._ready.is_set():
            tail = " | ".join(list(self.log_tail)[-5:])
            self.error = f"broker did not start: {tail or 'no output'}"
            log.error("MQTT %s", self.error)
            await self._terminate()
            return False
        self.started_at = utcnow()
        await self._start_reader()
        self.anonymous_refused = await asyncio.to_thread(self._anonymous_check)
        log.info("MQTT broker %s running (pid %s, TLS port %s)", self.version, self.proc.pid,
                 self.tls_port if self.tls else "off")
        return True

    async def _supervise(self) -> None:
        """Restart the broker if it exits on its own."""
        attempt = 0
        while not self._stopping:
            if self.running:
                await self.proc.wait()
                if self._stopping:
                    return
                self.error = f"broker exited (code {self.proc.returncode}): " + " | ".join(list(self.log_tail)[-3:])
                log.error("MQTT %s", self.error)
                self._stop_reader()
            await asyncio.sleep(RESTART_DELAYS[min(attempt, len(RESTART_DELAYS) - 1)])
            attempt += 1
            self.restarts += 1
            if await self._launch():
                attempt = 0

    async def _terminate(self) -> None:
        if self.proc is None or self.proc.returncode is not None:
            return
        self.proc.terminate()
        try:
            await asyncio.wait_for(self.proc.wait(), 5)
        except asyncio.TimeoutError:
            self.proc.kill()
            await self.proc.wait()

    async def _reload(self) -> None:
        """SIGHUP, then wait until the broker says it reloaded (and a moment for it to re-check clients)."""
        if not self.running:
            return
        self._reloaded = asyncio.Event()
        self.proc.send_signal(signal.SIGHUP)
        try:
            await asyncio.wait_for(self._reloaded.wait(), 3)
        except asyncio.TimeoutError:
            log.warning("MQTT broker did not confirm the reload")
        await asyncio.sleep(0.1)

    async def _wait_gone(self, usernames: Sequence[str], timeout: float = 3.0) -> None:
        deadline = asyncio.get_running_loop().time() + timeout
        while any(c["username"] in usernames for c in self._conns.values()):
            if asyncio.get_running_loop().time() > deadline:
                return
            await asyncio.sleep(0.05)

    # ---- files -------------------------------------------------------------------------------------------------

    def _write_accounts(self, accounts: Sequence[BrokerAccount]) -> None:
        mq.write_private(self.layout.passwd, mq.render_passwd(mq.password_hash(self._reader_password), accounts))
        mq.write_private(self.layout.acl, mq.render_acl(accounts))
        self._hand_to_broker_user()

    def _copy_tls(self) -> bool:
        """The broker presents the OTProbe server certificate (same host, same CA the agents pin)."""
        files = (self.cert_file, self.key_file, self.ca_file)
        if not all(f and Path(f).is_file() for f in files):
            return False
        shutil.copyfile(self.cert_file, self.layout.cert)
        shutil.copyfile(self.ca_file, self.layout.ca)
        mq.write_private(self.layout.key, Path(self.key_file).read_text())
        return True

    def _hand_to_broker_user(self) -> None:
        """Mosquitto started as root drops to the 'mosquitto' user, which must be able to read its files."""
        if os.geteuid() != 0:
            return
        import pwd
        try:
            user = pwd.getpwnam("mosquitto")
        except KeyError:
            return
        for path in [self.layout.root, *self.layout.root.rglob("*")]:
            os.chown(path, user.pw_uid, user.pw_gid)

    # ---- broker log --------------------------------------------------------------------------------------------

    async def _read_log(self, proc: asyncio.subprocess.Process) -> None:
        assert proc.stdout is not None
        async for raw in proc.stdout:
            line = raw.decode(errors="replace").rstrip()
            if not line:
                continue
            self.log_tail.append(line)
            self.on_log(line)

    def on_log(self, line: str) -> None:
        ev = mq.parse_log(line)
        if ev is None:
            return
        now = utcnow()
        if ev.kind == "running":
            self.version = ev.detail
            if self._ready is not None:
                self._ready.set()
        elif ev.kind == "reloaded":
            if self._reloaded is not None:
                self._reloaded.set()
        elif ev.kind == "connected" and ev.username != mq.READER:
            self._conns[ev.client_id] = {"username": ev.username, "client_id": ev.client_id, "ip": ev.ip,
                                         "connected_at": now}
            self.last_seen[ev.username] = {"ip": ev.ip, "clientId": ev.client_id, "at": now}
        elif ev.kind == "refused":
            self._conns.pop(ev.client_id, None)
            if not ev.client_id.startswith(CHECK_CLIENT):      # OTProbe's own anonymous-login check
                self.refused.append({"clientId": ev.client_id, "ip": ev.ip, "at": now})
        elif ev.kind == "disconnected":
            self._conns.pop(ev.client_id, None)

    def connections(self) -> list[dict[str, Any]]:
        return [dict(c) for c in self._conns.values()]

    # ---- OTProbe's reader --------------------------------------------------------------------------------------

    async def _start_reader(self) -> None:
        connected = asyncio.Event()
        loop = self._loop
        client = paho.Client(paho.CallbackAPIVersion.VERSION2, client_id=f"{mq.READER}-{secrets.token_hex(4)}",
                             clean_session=True, protocol=paho.MQTTv311)
        client.username_pw_set(mq.READER, self._reader_password)
        client.reconnect_delay_set(1, 30)

        def on_connect(c, userdata, flags, reason, properties):
            if not reason.is_failure:
                c.subscribe("#", qos=0)
                loop.call_soon_threadsafe(connected.set)

        def on_message(c, userdata, msg):
            if self.on_message is not None:
                loop.call_soon_threadsafe(self.on_message, msg.topic, bytes(msg.payload), bool(msg.retain))

        client.on_connect, client.on_message = on_connect, on_message
        client.connect_async("127.0.0.1", self._internal_port, keepalive=30)
        client.loop_start()
        self._reader = client
        try:
            await asyncio.wait_for(connected.wait(), 5)
        except asyncio.TimeoutError:
            self.error = "OTProbe could not log in to its own broker"
            log.error("MQTT %s", self.error)

    def _stop_reader(self) -> None:
        if self._reader is not None:
            self._reader.disconnect()
            self._reader.loop_stop()
            self._reader = None

    def _anonymous_check(self) -> bool | None:
        """MQTT-BRK-001: a CONNECT without credentials must be refused."""
        result: list[bool] = []
        c = paho.Client(paho.CallbackAPIVersion.VERSION2, client_id=f"{CHECK_CLIENT}{secrets.token_hex(4)}")
        c.on_connect = lambda cl, u, f, reason, p: result.append(reason.is_failure)
        try:
            c.connect("127.0.0.1", self._internal_port, keepalive=5)
            for _ in range(30):
                c.loop(timeout=0.1)
                if result:
                    break
        except OSError:
            return None
        finally:
            c.disconnect()
        return result[0] if result else True        # no CONNACK at all: the broker closed the connection

    # ---- status ------------------------------------------------------------------------------------------------

    def listeners(self) -> list[dict[str, Any]]:
        out = []
        if self.tls and self.tls_port:
            out.append({"port": self.tls_port, "tls": True, "bind": self.bind or "all interfaces"})
        if self.plain_port:
            out.append({"port": self.plain_port, "tls": False, "bind": self.bind or "all interfaces"})
        return out

    def checks(self) -> list[dict[str, Any]]:
        def check(rule, title, severity, passed, detail):
            return {"ruleId": rule, "title": title, "severity": severity, "detail": detail,
                    "status": "UNKNOWN" if passed is None else ("PASS" if passed else "FAIL")}

        cert_ok, cert_detail = self._cert_days()
        prefixes_ok = all(mq.valid_prefix(a.topic_prefix) for a in self.accounts)
        return [
            check("MQTT-BRK-001", "Anonymous access is refused", "CRITICAL", self.anonymous_refused,
                  {True: "a connection without credentials was refused", False: "the broker accepted a connection "
                   "without credentials", None: "not checked yet"}[self.anonymous_refused]),
            check("MQTT-BRK-002", "No unencrypted listener", "MEDIUM", not self.plain_port,
                  f"plain MQTT is on, port {self.plain_port}" if self.plain_port else "devices must use TLS"),
            check("MQTT-BRK-003", "No account can publish to every topic", "HIGH", prefixes_ok,
                  "every device account is limited to its own topic prefix" if prefixes_ok
                  else "an account has a topic prefix with wildcards"),
            check("MQTT-BRK-004", "Server certificate valid for more than 30 days", "MEDIUM", cert_ok, cert_detail),
        ]

    def _cert_days(self) -> tuple[bool | None, str]:
        if not self.tls:
            return False, ("no server certificate (OTPROBE_TLS_CA_FILE and the server certificate next to it, or "
                           "MQTT_TLS_CERT_FILE / MQTT_TLS_KEY_FILE): the TLS listener is off")
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(self.layout.cert.read_bytes())
        left = cert.not_valid_after_utc - utcnow()
        return left > timedelta(days=30), f"expires {cert.not_valid_after_utc:%Y-%m-%d} ({left.days} days)"

    def status(self) -> dict[str, Any]:
        return {"mode": "bundled", "running": self.running, "pid": self.proc.pid if self.running else None,
                "version": self.version, "binary": self.binary, "startedAt": self.started_at,
                "restarts": self.restarts, "error": self.error, "host": self.public_host,
                "listeners": self.listeners(), "checks": self.checks(), "connected": len(self._conns),
                "refused": list(self.refused), "log": list(self.log_tail)[-40:]}
