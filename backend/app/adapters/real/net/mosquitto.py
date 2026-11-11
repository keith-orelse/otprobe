"""Files and log lines of the bundled Mosquitto broker (docs/MQTT_BROKER.md, DECISIONS L6-10).

OTProbe owns every file in the broker folder and rewrites them at start-up and on each account change, then sends the
broker SIGHUP. The broker re-reads the password and ACL files and disconnects clients whose account is gone."""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from app.adapters.base import BrokerAccount
from app.core.mqtt_topics import READER, owner, password_hash, valid_prefix  # noqa: F401 (re-exported)

BINARY_PATHS = ("/opt/homebrew/sbin/mosquitto", "/usr/local/sbin/mosquitto", "/usr/sbin/mosquitto")


def find_binary(configured: str = "") -> str | None:
    if configured:
        return configured if Path(configured).is_file() else None
    found = shutil.which("mosquitto")
    return found or next((p for p in BINARY_PATHS if Path(p).is_file()), None)


@dataclass(frozen=True)
class Layout:
    """The broker folder (MQTT_DIR)."""
    root: Path

    @property
    def config(self) -> Path:
        return self.root / "mosquitto.conf"

    @property
    def passwd(self) -> Path:
        return self.root / "passwd"

    @property
    def acl(self) -> Path:
        return self.root / "acl"

    @property
    def data(self) -> Path:
        return self.root / "data"

    @property
    def ca(self) -> Path:
        return self.root / "ca.pem"

    @property
    def cert(self) -> Path:
        return self.root / "server.pem"

    @property
    def key(self) -> Path:
        return self.root / "server.key"


@dataclass(frozen=True)
class Listeners:
    internal_port: int                  # 127.0.0.1 only, for OTProbe's own reader
    tls_port: int = 8883                # devices, TLS (0 = off)
    plain_port: int = 0                 # devices, no TLS (off unless an admin turns it on)
    bind: str = ""                      # "" = every interface


def render_config(layout: Layout, listeners: Listeners, tls: bool, run_as: str | None = None) -> str:
    lines = [
        "# Written by OTProbe at start-up. Local changes are overwritten (docs/MQTT_BROKER.md).",
        "allow_anonymous false",
        f"password_file {layout.passwd}",
        f"acl_file {layout.acl}",
        "persistence true",
        f"persistence_location {layout.data}/",
        "log_dest stdout",
        *(f"log_type {t}" for t in ("error", "warning", "notice", "information")),
        "connection_messages true",
        "log_timestamp false",
        "max_packet_size 262144",
        "max_inflight_messages 20",
        "max_queued_messages 1000",
    ]
    if run_as:
        lines.append(f"user {run_as}")
    lines += ["", f"listener {listeners.internal_port} 127.0.0.1"]
    bind = f" {listeners.bind}" if listeners.bind else ""
    if tls and listeners.tls_port:
        lines += ["", f"listener {listeners.tls_port}{bind}", "max_connections 1000", f"cafile {layout.ca}",
                  f"certfile {layout.cert}", f"keyfile {layout.key}"]
    if listeners.plain_port:
        lines += ["", f"listener {listeners.plain_port}{bind}", "max_connections 1000"]
    return "\n".join(lines) + "\n"


def render_passwd(reader_hash: str, accounts: Sequence[BrokerAccount]) -> str:
    rows = [f"{READER}:{reader_hash}"] + [f"{a.username}:{a.password_hash}" for a in accounts if a.enabled]
    return "\n".join(rows) + "\n"


def render_acl(accounts: Sequence[BrokerAccount]) -> str:
    """The reader may read everything and publish nothing; each device may publish under its prefix only and read
    nothing. Accounts not listed (including disabled ones) can do nothing."""
    out = [f"user {READER}", "topic read #", "topic read $SYS/#", ""]
    for a in accounts:
        if a.enabled:
            out += [f"user {a.username}", f"topic write {a.topic_prefix}", f"topic write {a.topic_prefix}/#", ""]
    return "\n".join(out)


def write_private(path: Path, text: str) -> None:
    """Owner-only, and atomic: a reload never reads a half-written file."""
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


# ---- log lines (log_dest stdout, connection_messages true) -------------------------------------------------------

CONNECTED = re.compile(r"^New client connected from (?P<ip>.+):(?P<port>\d+) as (?P<cid>.+?) "
                       r"\(p\d.*?(?:u'(?P<user>[^']*)')?\)\.?$")
DISCONNECTED = re.compile(r"^Client (?P<cid>.+?) (?:\[(?P<ip>.+):(?P<port>\d+)\] )?"
                          r"(?:disconnected|closed its connection)"
                          r"(?::? ?(?P<why>.*?))?\.?$")
REFUSED = re.compile(r"^Client (?P<cid>.+?) \[(?P<ip>.+):(?P<port>\d+)\] disconnected: not authori[sz]ed\.?$")
VERSION = re.compile(r"^mosquitto version (?P<version>\S+) running")
RELOADED = "Reloading config."


@dataclass(frozen=True)
class LogEvent:
    kind: str                           # connected | disconnected | refused | running | reloaded
    client_id: str = ""
    ip: str = ""
    username: str = ""
    detail: str = ""


def parse_log(line: str) -> LogEvent | None:
    line = re.sub(r"^\d+: ", "", line.strip())      # timestamps appear before the config is loaded
    if m := CONNECTED.match(line):
        return LogEvent("connected", m["cid"], m["ip"].strip("[]"), m["user"] or "")
    if m := REFUSED.match(line):
        return LogEvent("refused", m["cid"], m["ip"].strip("[]"))
    if m := DISCONNECTED.match(line):
        return LogEvent("disconnected", m["cid"], (m["ip"] or "").strip("[]"), detail=m["why"] or "")
    if m := VERSION.match(line):
        return LogEvent("running", detail=m["version"])
    if line == RELOADED:
        return LogEvent("reloaded")
    return None
