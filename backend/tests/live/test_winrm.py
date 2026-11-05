"""WinRM / WMI without a Windows host: read-only script allow-list, parameter injection, mapping of recorded Windows
output, and the session stages against real sockets on 127.0.0.1 (closed port; TLS server with an untrusted and
then a trusted self-signed certificate). The full WinRM exchange is verified on a Windows lab host (LIVE_TEST_PLAN
stage 3)."""

from __future__ import annotations

import asyncio
import datetime as dt
import re
import socket
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.adapters.base import Credential, RemoteOperation, RemoteSession, ResultStatus, Target
from app.adapters.real.net import winrm
from app.adapters.real.net.gate import NetworkGate
from app.adapters.real.winrm import (
    RealWinRmAdapter,
    map_antivirus,
    map_firewall,
    map_network,
    map_os,
    map_software,
)

pytestmark = pytest.mark.live
WRITE_VERBS = re.compile(r"\b(Set|New|Remove|Stop|Start|Restart|Add|Enable|Disable|Install|Uninstall|Invoke|Clear|"
                         r"Rename|Move|Copy|Out|Register|Unregister|Suspend|Resume|Update|Write)-\w+|\biex\b|"
                         r"EncodedCommand|DownloadString|\[System\.IO\.File\]", re.I)


def gate() -> NetworkGate:
    g = NetworkGate()
    g.load([{"id": "lo", "cidr": "127.0.0.1/32", "kind": "INCLUDE", "profile": "IT"}], armed=True, safe_mode=False)
    return g


def test_every_script_is_read_only():
    bad = {name: WRITE_VERBS.findall(text) for name, text in winrm.SCRIPTS.items() if WRITE_VERBS.search(text)}
    assert not bad, bad


@pytest.mark.parametrize("params", [{"name": "x'; Stop-Computer -Force; '"}, {"name": "a b"}, {"server": "h;calc"},
                                    {"port": "443; Remove-Item C:\\"}, {"evil": "1"}])
def test_parameters_cannot_inject_commands(params):
    script = "q_service" if "name" in params else "q_server_connectivity"
    with pytest.raises(ValueError):
        winrm.render(script, {"name": "WinRM", "server": "otprobe.local", "port": "443", **params})
    with pytest.raises(ValueError):
        winrm.render("Remove-Item C:\\")


def test_mapping_windows_11_with_defender():
    os_ = map_os({"caption": "Microsoft Windows 11 Enterprise", "version": "10.0.26100", "build": "26100", "ubr": 2314,
                  "displayVersion": "24H2", "hostname": "ENG-WS-07", "domain": "plant.local", "partOfDomain": True,
                  "lastBoot": (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=5)).isoformat()})
    assert os_["os.product"] == "Windows 11 Enterprise" and os_["os.build"] == "26100.2314"
    assert os_["os.version"] == "24H2" and os_["identity.domain"] == "plant.local"
    assert 17900 < os_["hardware.uptime_sec"] < 18100
    av = map_antivirus({"defender": {"service": True, "realtime": True, "signatureAge": 1}, "securityCenter": []})
    assert av == {"antivirus.product": "Microsoft Defender Antivirus", "antivirus.state": "running",
                  "antivirus.realtime": True, "antivirus.signature_age_days": 1}
    fw = map_firewall([{"name": "Domain", "enabled": True, "inbound": "NotConfigured"},
                       {"name": "Private", "enabled": True, "inbound": "NotConfigured"},
                       {"name": "Public", "enabled": False, "inbound": "NotConfigured"}])
    assert fw["firewall.state"] == "partial" and fw["firewall.profiles"]["public"] == "off"


def test_mapping_server_without_defender_and_single_element_arrays():
    assert map_antivirus({"defender": None, "securityCenter": []}) == {}      # unknown, never "stopped"
    av = map_antivirus({"defender": None, "securityCenter": {"name": "Sophos Endpoint", "state": 266240}})
    assert av == {"antivirus.product": "Sophos Endpoint", "antivirus.state": "running"}
    assert map_firewall({"name": "Domain", "enabled": True, "inbound": "Block"})["firewall.state"] == "enabled"
    sw = map_software({"name": "AnyDesk", "version": "8.0.9", "publisher": "AnyDesk Software GmbH"})
    assert sw == {"software.installed": [{"name": "AnyDesk", "version": "8.0.9"}]}
    net = map_network({"interfaces": {"name": "Ethernet0", "ip": "10.20.1.15", "prefix": 24,
                                      "mac": "00-1A-2B-3C-4D-5E"}, "listening": 5986,
                       "connections": {"remote_ip": "10.20.2.10", "remote_port": 102}})
    assert net["network.interfaces"][0]["mac"] == "00:1A:2B:3C:4D:5E" and net["network.listening"] == [5986]
    assert net["network.connections"] == [{"remote_ip": "10.20.2.10", "remote_port": 102, "protocol": "tcp"}]


async def test_operations_that_change_a_host_are_refused_without_sending():
    adapter = RealWinRmAdapter(gate())
    adapter._sessions["s1"] = Target("127.0.0.1", port=5986, credential=Credential("p", "u", "x"))
    for op in (RemoteOperation.INSTALL_AGENT, RemoteOperation.STOP_SERVICE, RemoteOperation.REMOVE_FILES,
               RemoteOperation.UNINSTALL_AGENT):
        res = await adapter.execute(RemoteSession("s1", "127.0.0.1", []), op, {})
        assert res.status == ResultStatus.NOT_SUPPORTED and "phase L4" in res.error_detail
    assert adapter.gate.totals.as_dict()["sent"] == 0


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def self_signed(cn: str):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()).decode())


@pytest.fixture
async def tls_server(tmp_path):
    cert_pem, key_pem = self_signed("eng-ws-07.plant.local")
    (tmp_path / "c.pem").write_text(cert_pem)
    (tmp_path / "k.pem").write_text(key_pem)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    received: list[bytes] = []

    async def handle(reader, writer):
        try:
            received.append(await asyncio.wait_for(reader.read(4096), 2))
        except (asyncio.TimeoutError, ConnectionError, ssl.SSLError):
            pass
        writer.close()

    port = free_port()
    server = await asyncio.start_server(handle, "127.0.0.1", port, ssl=ctx)
    async with server:
        yield {"port": port, "cert": cert_pem, "received": received}


async def stages_of(cred: Credential, port: int):
    adapter, seen = RealWinRmAdapter(gate()), []

    async def on_stage(st):
        seen.append((st.name, st.status.value, st.detail))

    res, session = await adapter.open_session(Target("127.0.0.1", port=port, credential=cred), on_stage)
    return res, session, seen, None


async def test_closed_port_fails_at_connecting():
    res, session, seen, _ = await stages_of(Credential("OT-WINDOWS-READONLY", "u", "p"), free_port())
    assert session is None and res.status == ResultStatus.REFUSED
    assert seen[-1][0] == "CONNECTING" and seen[-1][1] == "REFUSED"


async def test_untrusted_certificate_stops_before_any_credential_is_sent(tls_server):
    res, session, seen, _ = await stages_of(Credential("OT-WINDOWS-READONLY", "svc-otprobe", "s3cret-pass"),
                                         tls_server["port"])
    assert session is None and res.status == ResultStatus.TLS_INVALID
    assert [s[0] for s in seen] == ["CONNECTING", "TCP_OK", "TLS_VALIDATED"] and seen[-1][1] == "TLS_INVALID"
    assert "certificate" in seen[-1][2].lower()
    assert res.data["services.winrm.tls"] == "invalid"
    assert all(b"s3cret" not in r for r in tls_server["received"])


async def test_trusted_certificate_passes_tls_then_fails_at_authentication(tls_server):
    cred = Credential("OT-WINDOWS-READONLY", "svc-otprobe", "s3cret-pass", {"caPem": tls_server["cert"]})
    res, session, seen, _ = await stages_of(cred, tls_server["port"])
    names = [s[0] for s in seen]
    assert names[:3] == ["CONNECTING", "TCP_OK", "TLS_VALIDATED"] and seen[2][1] == "OK"
    assert "CN=eng-ws-07.plant.local" in seen[2][2]
    assert session is None and res.status != ResultStatus.OK and names[-1] in ("AUTH_OK", "SESSION_CREATED")


async def test_probe_reports_untrusted_winrm_certificate(live, tls_server):
    from tests.live.test_live_loopback import add_scope, safe_mode

    await add_scope(live)
    await safe_mode(live, False)
    await live.login("admin")
    r = await live.client.put("/api/v1/vault/profiles/OT-WINDOWS-READONLY", json={
        "protocol": "WinRM", "username": "svc-otprobe", "secret": "s3cret-pass",
        "params": {"port": tls_server["port"]}})
    assert r.status_code == 200, r.text
    await live.login("operator")
    await live.post("/discovery/jobs", {"targets": ["127.0.0.1/32"], "methods": ["ICMP"]}, expect=202)
    await live.idle()
    asset = await live.asset_by_ip("127.0.0.1")
    r = await live.post(f"/assets/{asset['id']}/probes", expect=202)
    await live.idle()
    probe = await live.get(f"/probes/{r.json()['id']}")
    steps = {s["name"]: s for s in probe["steps"]}
    assert steps["WINRM"]["status"] == "FAILED" and "certificate" in steps["WINRM"]["detail"].lower()
    assert [st["name"] for st in steps["WINRM"]["data"]["stages"]] == ["CONNECTING", "TCP_OK", "TLS_VALIDATED"]
    assert steps["WMI"]["status"] == "SKIPPED" and probe["status"] == "PARTIAL"
    assert (await live.get("/audit-events", params={"action": "WINRM_TLS_INVALID"}))["items"]


def test_link_local_adapters_are_not_interfaces():
    wifi = {"name": "Wi-Fi", "ip": "192.168.0.119", "prefix": 24, "mac": "54-13-79-6C-4C-91"}
    net = map_network({"interfaces": [wifi,
                                      {"name": "Bluetooth Network Connection", "ip": "169.254.98.99", "prefix": 16},
                                      {"name": "Ethernet", "ip": "169.254.183.178", "prefix": 16}],
                       "listening": [], "connections": []})
    assert [i["name"] for i in net["network.interfaces"]] == ["Wi-Fi"]


def test_windows_10_home_is_flagged_as_unsupported():
    import yaml

    from tests.unit.test_design_artifacts import RULES_DIR
    params = yaml.safe_load((RULES_DIR / "windows_engineering_baseline.yaml").read_text())["parameters"]
    unsupported = params["unsupported_os_products"]
    assert map_os({"caption": "Microsoft Windows 10 Home"})["os.product"] in unsupported      # found on a real laptop
    assert "Windows 10 Enterprise LTSC 2021" not in unsupported and "Windows 11 Home" not in unsupported


async def test_certificate_name_is_shown_when_validation_is_skipped(tls_server):
    cred = Credential("OT-WINDOWS-READONLY", "svc-otprobe", "s3cret-pass", {"skipCertCheck": True})
    res, session, seen, _ = await stages_of(cred, tls_server["port"])
    tls = next(s for s in seen if s[0] == "TLS_VALIDATED")
    assert tls[1] == "OK" and "CN=eng-ws-07.plant.local" in tls[2] and "validation skipped" in tls[2]
