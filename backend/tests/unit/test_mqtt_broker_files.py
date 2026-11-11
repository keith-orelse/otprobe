"""The bundled broker's files and log parsing (app/adapters/real/net/mosquitto.py), the shared topic rules
(app/core/mqtt_topics.py) and how telemetry payloads become rule evidence."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from app.adapters.base import BrokerAccount
from app.adapters.real.mqtt import decode
from app.adapters.real.net import mosquitto as mq
from app.core.mqtt_topics import check_password, overlaps, owner, password_hash, valid_prefix, valid_username
from app.services.telemetry import evidence

SENSOR = BrokerAccount("sensor01", password_hash("pw-1"), "plant/line1/sensor01")
OFF = BrokerAccount("old-plc", password_hash("pw-2"), "plant/line2/plc01", enabled=False)


def test_password_hash_is_mosquittos_pbkdf2_format():
    h = password_hash("s3cret-pass")
    assert h.startswith("$7$1000$") and check_password("s3cret-pass", h) and not check_password("other", h)
    assert password_hash("x", salt=b"0" * 12) == password_hash("x", salt=b"0" * 12)


@pytest.mark.skipif(shutil.which("mosquitto_passwd") is None and not Path("/opt/homebrew/bin/mosquitto_passwd")
                    .exists(), reason="mosquitto_passwd not installed")
def test_hashes_written_by_mosquitto_passwd_verify_here(tmp_path):
    tool = shutil.which("mosquitto_passwd") or "/opt/homebrew/bin/mosquitto_passwd"
    subprocess.run([tool, "-c", "-b", str(tmp_path / "pw"), "alice", "secret-123"], check=True, capture_output=True)
    stored = (tmp_path / "pw").read_text().strip().split(":", 1)[1]
    assert check_password("secret-123", stored) and not check_password("secret-124", stored)


def test_usernames_and_prefixes():
    assert valid_username("sensor01") and valid_username("line1.plc-02")
    assert not valid_username("otprobe-reader") and not valid_username("Sensor") and not valid_username("ab")
    for ok in ("plant", "plant/line1/sensor01", "site-a/area_2/v1.0"):
        assert valid_prefix(ok), ok
    for bad in ("", "#", "plant/#", "plant/+/x", "$SYS/broker", "/plant", "plant/", "plant//x", "a b",
                "/".join(["l"] * 11)):
        assert not valid_prefix(bad), bad


def test_prefixes_never_overlap_and_each_topic_has_one_owner():
    assert overlaps("plant/line1", "plant/line1/sensor01") and overlaps("a/b", "a/b")
    assert not overlaps("plant/line1", "plant/line10") and not overlaps("plant/a", "plant/b")
    accounts = [SENSOR, BrokerAccount("gw", "", "plant/line10")]
    assert owner("plant/line1/sensor01/temperature", accounts) == "sensor01"
    assert owner("plant/line1/sensor01", accounts) == "sensor01"
    assert owner("plant/line10/x", accounts) == "gw" and owner("plant/line1/sensor02/t", accounts) is None


def test_acl_and_password_files():
    acl = mq.render_acl([SENSOR, OFF])
    assert acl.split("\n\n")[0] == "user otprobe-reader\ntopic read #\ntopic read $SYS/#"
    assert "user sensor01\ntopic write plant/line1/sensor01\ntopic write plant/line1/sensor01/#" in acl
    assert "old-plc" not in acl and "topic read plant" not in acl            # devices read nothing
    passwd = mq.render_passwd(password_hash("r"), [SENSOR, OFF])
    assert [line.split(":")[0] for line in passwd.split()] == ["otprobe-reader", "sensor01"]


def test_config_is_locked_down():
    layout = mq.Layout(Path("/data/mqtt"))
    conf = mq.render_config(layout, mq.Listeners(41000, 8883, 0, ""), tls=True)
    assert "allow_anonymous false" in conf and "listener 41000 127.0.0.1" in conf
    assert "listener 8883\nmax_connections 1000\ncafile /data/mqtt/ca.pem" in conf
    assert "1883" not in conf and "user " not in conf
    no_tls = mq.render_config(layout, mq.Listeners(41000, 8883, 1883, "192.168.0.160"), tls=False)
    assert "listener 8883" not in no_tls and "listener 1883 192.168.0.160" in no_tls


def test_log_lines():
    ev = mq.parse_log("New client connected from 192.168.0.42:51234 as sensor-A (p2, c1, k60, u'sensor01').")
    assert (ev.kind, ev.ip, ev.client_id, ev.username) == ("connected", "192.168.0.42", "sensor-A", "sensor01")
    ev = mq.parse_log("1794305005: New client connected from ::1:4000 as x y (p4, c1, k60, u'gw').")
    assert (ev.ip, ev.client_id, ev.username) == ("::1", "x y", "gw")
    assert mq.parse_log("Client sensor-A [192.168.0.42:51234] disconnected.").kind == "disconnected"
    assert mq.parse_log("Client sensor-A closed its connection.").kind == "disconnected"
    ev = mq.parse_log("Client again [127.0.0.1:49410] disconnected: not authorised.")
    assert (ev.kind, ev.client_id, ev.ip) == ("refused", "again", "127.0.0.1")
    assert mq.parse_log("mosquitto version 2.1.2 running").detail == "2.1.2"
    assert mq.parse_log("Opening ipv4 listen socket on port 8883.") is None


def test_payloads_and_rule_evidence():
    assert decode(b"42.5") == (True, 42.5) and decode(b'{"temperature": 41}') == (True, {"temperature": 41})
    assert decode(b"RUN\n") == (True, "RUN") and decode(b"\xff\x00\x10") == (False, "binary")
    assert decode(b"1" * 20_000) == (False, "oversize")
    t = "plant/line1/sensor01/temperature"
    assert evidence(t, 97) == {"temperature": 97, "mqtt": {"topic": t}}
    assert evidence(t, "97.5") == {"temperature": 97.5, "mqtt": {"topic": t}}
    assert evidence("plant/plc01/mode", "RUN")["mode"] == "RUN"
    assert evidence(t, {"temperature": 40, "unit": "C"}) == {"temperature": 40, "unit": "C", "mqtt": {"topic": t}}
    assert evidence(t, [1, 2]) == {"mqtt": {"topic": t}} and evidence(t, True) == {"mqtt": {"topic": t}}
