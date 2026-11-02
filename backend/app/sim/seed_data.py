"""Seed definition of the simulated plant. See docs/SIMULATED_NETWORK.md (★ values are test-relevant)."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from app.core import demo_credentials as dc

WIN_ACCOUNTS = {dc.WINDOWS_READONLY[2]: dc.WINDOWS_READONLY[3], dc.WINDOWS_INSTALLER[2]: dc.WINDOWS_INSTALLER[3]}
SNMP_USER = {"username": dc.SNMPV3_RO[2], "secret": dc.SNMPV3_RO[3], "auth": "SHA-256", "priv": "AES-128"}
SSH_ACCOUNTS = {dc.LINUX_SSH_RO[2]: dc.LINUX_SSH_RO[3]}
CONDUIT_MAC = "00:1A:2B:3C:FE:01"

WIN_SERVICES = [
    {"name": "WinRM", "display": "Windows Remote Management", "state": "running", "start_type": "auto"},
    {"name": "WinDefend", "display": "Microsoft Defender Antivirus Service", "state": "running", "start_type": "auto"},
    {"name": "EventLog", "display": "Windows Event Log", "state": "running", "start_type": "auto"},
    {"name": "mpssvc", "display": "Windows Defender Firewall", "state": "running", "start_type": "auto"},
    {"name": "Spooler", "display": "Print Spooler", "state": "running", "start_type": "auto"},
    {"name": "W32Time", "display": "Windows Time", "state": "running", "start_type": "manual"},
    {"name": "TermService", "display": "Remote Desktop Services", "state": "running", "start_type": "manual"},
]


def _fw(state: str) -> dict[str, Any]:
    on = "on" if state == "enabled" else "off"
    return {"state": state, "profiles": {"domain": on, "private": on, "public": on},
            "default_inbound": "block", "rule_count": 412}


def _av(state: str = "running") -> dict[str, Any]:
    return {"product": "Microsoft Defender Antivirus", "state": state, "signature_age_days": 1, "realtime": True}


def _windows(hostname: str, ip: str, mac: str, *, os_: dict, hardware: dict, software: list, installed: list,
             missing: list, admins: list, password: dict, audit: str, usb: str | None, listening: list,
             connections: list, extra_services: list | None = None) -> dict[str, Any]:
    state: dict[str, Any] = {
        "icmp": "ONLINE", "rtt_ms": 1.4,
        "snmp": None,
        "winrm": {"enabled": True, "port": 5986, "cert": "valid", "cert_cn": f"{hostname}.demo.local"},
        "ssh": None,
        "accounts": dict(WIN_ACCOUNTS),
        "identity": {"hostname": hostname, "domain": "DEMO", "fqdn": f"{hostname}.demo.local"},
        "os": os_,
        "hardware": hardware,
        "firewall": _fw("enabled"),
        "antivirus": _av(),
        "patches": {"installed": installed, "missing": missing},
        "software": software,
        "services": deepcopy(WIN_SERVICES) + (extra_services or []),
        "local_admins": admins,
        "password_policy": password,
        "audit": {"logon_events": audit, "process_creation": "no_auditing"},
        "network": {
            "interfaces": [{"name": "Ethernet0", "ip": ip, "mac": mac, "prefix": 24, "gateway": "192.168.20.254"}],
            "listening": listening,
            "connections": connections,
        },
        "reboot_pending": False,
        "files": {},
    }
    if usb is not None:
        state["usb"] = {"storage_policy": usb}
    return state


def _app(name: str, version: str, publisher: str, scope: str = "machine") -> dict[str, str]:
    return {"name": name, "version": version, "publisher": publisher, "scope": scope}


def _switch_state() -> dict[str, Any]:
    port_map = [CONDUIT_MAC, "00:1A:2B:3C:20:13", "00:1A:2B:3C:20:14", "00:1A:2B:3C:21:39", "00:1A:2B:3C:21:49",
                "00:1A:2B:3C:10:10", "00:1A:2B:3C:10:11", "00:1A:2B:3C:10:20", "00:1A:2B:3C:10:21"]
    interfaces = []
    for n in range(1, 25):
        mac = port_map[n - 1] if n <= len(port_map) else None
        interfaces.append({"index": n, "name": f"Gi1/{n}", "oper_status": "up" if mac else "down",
                           "speed_mbps": 1000 if mac else 0, "neighbor_mac": mac,
                           "description": "uplink to fw-conduit-01" if n == 1 else ""})
    return {
        "icmp": "ONLINE", "rtt_ms": 0.9,
        "snmp": {"user": SNMP_USER, "read_only": True, "sys_name": "industrial-switch-01",
                 "sys_descr": "IndustrialNet IMS-2400 (demo data) managed industrial switch, IMS-OS 5.4.2",
                 "sys_object_id": "1.3.6.1.4.1.99999.1.24", "uptime_sec": 3_888_000, "interfaces": interfaces,
                 "entity": {"vendor": "IndustrialNet (demo data)", "model": "IMS-2400", "firmware": "IMS-OS 5.4.2"}},
        "winrm": None, "ssh": None, "accounts": {},
        "identity": {"hostname": "industrial-switch-01"},
        "network": {"listening": [161], "connections": []},
    }


def _plc_state(sys_name: str, descr: str, vendor: str, model: str, cpu: str, firmware: str) -> dict[str, Any]:
    return {
        "icmp": "ONLINE", "rtt_ms": 2.1,
        "snmp": {"user": SNMP_USER, "read_only": True, "sys_name": sys_name, "sys_descr": descr,
                 "sys_object_id": "1.3.6.1.4.1.99999.2.1", "uptime_sec": 9_504_000, "interfaces": [],
                 "entity": {"vendor": vendor, "model": model, "firmware": firmware},
                 "plc": {"mode": "RUN", "cpu": cpu, "firmware": firmware}},
        "winrm": None, "ssh": None, "accounts": {},
        "identity": {"hostname": sys_name},
        "network": {"listening": [102, 161], "connections": []},
    }


def _sensor_state(name: str) -> dict[str, Any]:
    return {"icmp": "BLOCKED", "rtt_ms": None, "snmp": None, "winrm": None, "ssh": None, "accounts": {},
            "identity": {"hostname": name}, "network": {"listening": [], "connections": []}}


DEVICES: list[dict[str, Any]] = [
    {
        "device_id": "dev-server", "ip": "192.168.35.72", "mac": "00:1A:2B:3C:35:72", "hostname": "otprobe-server",
        "vendor": "OTProbe", "model": "Probe Server", "device_type": "Probe Server", "level": "DMZ",
        "state": {"icmp": "ONLINE", "rtt_ms": 0.3, "snmp": None, "winrm": None, "ssh": None, "accounts": {},
                  "identity": {"hostname": "otprobe-server"}, "network": {"listening": [443], "connections": []}},
    },
    {
        "device_id": "dev-sw01", "ip": "192.168.20.1", "mac": "00:1A:2B:3C:20:01", "hostname": "industrial-switch-01",
        "vendor": "IndustrialNet (demo data)", "model": "IMS-2400", "device_type": "Switch", "level": "2",
        "state": _switch_state(),
    },
    {
        "device_id": "dev-ews01", "ip": "192.168.20.13", "mac": "00:1A:2B:3C:20:13", "hostname": "eng-ws-01",
        "vendor": "Dell-style (demo data)", "model": "Precision 3660 (demo data)",
        "device_type": "Engineering Workstation", "level": "2",
        "state": _windows(
            "eng-ws-01", "192.168.20.13", "00:1A:2B:3C:20:13",
            os_={"family": "windows", "name": "Microsoft Windows 11 Enterprise", "product": "Windows 11 Enterprise",
                 "version": "24H2", "build": "26100.2314"},
            hardware={"manufacturer": "Dell-style (demo data)", "model": "Precision 3660 (demo data)",
                      "cpu": "Intel Core i7-12700 (demo)", "ram_gb": 32,
                      "disk": [{"drive": "C:", "size_gb": 512, "free_gb": 318}], "uptime_sec": 533_000},
            software=[
                _app("Siemens-style TIA Portal V18 (demo data)", "18.0.0.2", "Demo Automation"),
                _app("Notepad++", "8.6.9", "Notepad++ Team"),
                _app("7-Zip", "24.08", "Igor Pavlov"),
                _app("Microsoft Visual C++ 2015-2022 Redistributable", "14.40.33810", "Microsoft Corporation"),
                _app("RemoteTool Demo", "3.2.0", "Demo Corp", scope="user"),
                _app("Zoom-style Meetings (demo data)", "6.1.0", "Demo Video", scope="user"),
            ],
            installed=["KB5044284", "KB5046617", "KB5043080"], missing=["KB5048667", "KB5050009"],
            admins=[{"name": "Administrator", "type": "user", "enabled": False},
                    {"name": "DEMO\\ot-admins", "type": "group", "enabled": True},
                    {"name": "DEMO\\eng-shared", "type": "user", "enabled": True},
                    {"name": "eng-ws-01\\support", "type": "user", "enabled": True}],
            password={"min_length": 14, "complexity": True, "lockout_threshold": 5, "max_age_days": 90},
            audit="success_and_failure", usb=None,  # ★ unverifiable -> UNKNOWN
            listening=[135, 445, 3389, 5986],
            connections=[{"remote_ip": "192.168.10.10", "remote_port": 102, "protocol": "S7comm"}],
        ),
    },
    {
        "device_id": "dev-ews02", "ip": "192.168.20.14", "mac": "00:1A:2B:3C:20:14", "hostname": "eng-ws-02",
        "vendor": "HP-style (demo data)", "model": "Z2 G5 (demo data)",
        "device_type": "Engineering Workstation", "level": "2",
        "state": _windows(
            "eng-ws-02", "192.168.20.14", "00:1A:2B:3C:20:14",
            os_={"family": "windows", "name": "Microsoft Windows 10 Enterprise", "product": "Windows 10 Enterprise",
                 "version": "22H2", "build": "19045.3803"},
            hardware={"manufacturer": "HP-style (demo data)", "model": "Z2 G5 (demo data)",
                      "cpu": "Intel Xeon W-1250 (demo)", "ram_gb": 16,
                      "disk": [{"drive": "C:", "size_gb": 256, "free_gb": 41}], "uptime_sec": 1_210_000},
            software=[_app("Siemens-style TIA Portal V16 (demo data)", "16.0.0.1", "Demo Automation"),
                      _app("Notepad++", "8.4.2", "Notepad++ Team")],
            installed=["KB5031356"], missing=[f"KB50{n}" for n in range(32189, 32203)],
            admins=[{"name": "Administrator", "type": "user", "enabled": False},
                    {"name": "DEMO\\ot-admins", "type": "group", "enabled": True},
                    {"name": "eng-ws-02\\maint", "type": "user", "enabled": True}],
            password={"min_length": 8, "complexity": True, "lockout_threshold": 0, "max_age_days": 365},
            audit="success", usb="blocked", listening=[135, 445, 5986],
            connections=[{"remote_ip": "192.168.10.11", "remote_port": 44818, "protocol": "EtherNet/IP"}],
        ),
    },
    {
        "device_id": "dev-scada01", "ip": "192.168.20.139", "mac": "00:1A:2B:3C:21:39", "hostname": "scada-01",
        "vendor": "Dell-style (demo data)", "model": "PowerEdge R650 (demo data)", "device_type": "SCADA Server",
        "level": "2",
        "state": _windows(
            "scada-01", "192.168.20.139", "00:1A:2B:3C:21:39",
            os_={"family": "windows", "name": "Microsoft Windows Server 2019 Standard",
                 "product": "Windows Server 2019 Standard", "version": "1809", "build": "17763.5329"},
            hardware={"manufacturer": "Dell-style (demo data)", "model": "PowerEdge R650 (demo data)",
                      "cpu": "Intel Xeon Silver 4314 (demo)", "ram_gb": 64,
                      "disk": [{"drive": "C:", "size_gb": 960, "free_gb": 512}], "uptime_sec": 4_320_000},
            software=[_app("WinCC-style SCADA Runtime (demo data)", "8.0.1", "Demo Automation"),
                      _app("OPC UA Server (demo data)", "1.5.2", "Demo Automation")],
            installed=["KB5034127"], missing=["KB5035849", "KB5036896", "KB5037765"],
            admins=[{"name": "Administrator", "type": "user", "enabled": False},
                    {"name": "DEMO\\scada-admins", "type": "group", "enabled": True}],
            password={"min_length": 14, "complexity": True, "lockout_threshold": 5, "max_age_days": 90},
            audit="success_and_failure", usb="blocked", listening=[135, 445, 4840, 5986],
            connections=[{"remote_ip": "192.168.10.10", "remote_port": 102, "protocol": "S7comm"},
                         {"remote_ip": "192.168.10.11", "remote_port": 44818, "protocol": "EtherNet/IP"},
                         {"remote_ip": "192.168.20.149", "remote_port": 5450, "protocol": "Historian ingest"}],
            extra_services=[{"name": "ScadaRuntime", "display": "SCADA Runtime (demo)", "state": "running",
                             "start_type": "auto"}],
        ) | {"icmp": "ONLINE", "rtt_ms": 180.0},
    },
    {
        "device_id": "dev-hist01", "ip": "192.168.20.149", "mac": "00:1A:2B:3C:21:49", "hostname": "historian-01",
        "vendor": "Generic x86 server (demo data)", "model": "x86 server (demo data)",
        "device_type": "Historian", "level": "2",
        "state": {
            "icmp": "ONLINE", "rtt_ms": 1.1,
            "snmp": {"user": SNMP_USER, "read_only": True, "sys_name": "historian-01",
                     "sys_descr": "Linux historian-01 5.15.0-105-generic x86_64",
                     "sys_object_id": "1.3.6.1.4.1.8072.3.2.10",
                     "uptime_sec": 2_592_000, "interfaces": [],
                     "entity": {"vendor": "Generic x86 server (demo data)", "model": "x86 server (demo data)",
                                "firmware": None}},
            "winrm": None, "ssh": {"port": 22}, "accounts": dict(SSH_ACCOUNTS),
            "identity": {"hostname": "historian-01"},
            "os": {"family": "linux", "name": "Ubuntu", "product": "Ubuntu 22.04.4 LTS", "version": "22.04.4",
                   "kernel": "5.15.0-105-generic"},
            "hardware": {"uptime_sec": 2_592_000},
            "network": {"listening": [22, 161, 5450, 8883], "connections": []},
        },
    },
    {
        "device_id": "dev-plc01", "ip": "192.168.10.10", "mac": "00:1A:2B:3C:10:10", "hostname": "plc-01",
        "vendor": "Siemens-style (demo data)", "model": "S7-1500 Demo", "device_type": "PLC", "level": "1",
        "state": _plc_state("plc-01", "Siemens-style S7-1500 Demo (demo data), CPU 1516-3 PN/DP, FW V2.9",
                            "Siemens-style (demo data)", "S7-1500 Demo CPU 1516-3 PN/DP", "CPU 1516-3 PN/DP", "V2.9"),
    },
    {
        "device_id": "dev-plc02", "ip": "192.168.10.11", "mac": "00:1A:2B:3C:10:11", "hostname": "plc-02",
        "vendor": "Rockwell-style (demo data)", "model": "ControlLogix 5580 Demo", "device_type": "PLC", "level": "1",
        "state": _plc_state("plc-02", "Rockwell-style ControlLogix 5580 Demo (demo data), FW 33.011",
                            "Rockwell-style (demo data)", "ControlLogix 5580 Demo", "1756-L83E (demo)", "33.011"),
    },
    {
        "device_id": "dev-ts01", "ip": "192.168.10.20", "mac": "00:1A:2B:3C:10:20", "hostname": "temperature-sensor-01",
        "vendor": "Generic IIoT (demo data)", "model": "PT100 transmitter (demo data)", "device_type": "Sensor",
        "level": "0", "state": _sensor_state("temperature-sensor-01"),
    },
    {
        "device_id": "dev-ps01", "ip": "192.168.10.21", "mac": "00:1A:2B:3C:10:21", "hostname": "pressure-sensor-01",
        "vendor": "Generic IIoT (demo data)", "model": "Pressure transmitter (demo data)", "device_type": "Sensor",
        "level": "0", "state": _sensor_state("pressure-sensor-01"),
    },
]

MQTT_CLIENTS = [
    {"client_id": "plc01", "device_id": "dev-plc01", "source_ip": "192.168.10.10",
     "topics": ["factory/line1/plc01/status"]},
    {"client_id": "sensor01", "device_id": "dev-ts01", "source_ip": "192.168.10.20",
     "topics": ["factory/line1/sensor01/temperature"]},
    {"client_id": "sensor02", "device_id": "dev-ps01", "source_ip": "192.168.10.21",
     "topics": ["factory/line1/sensor02/pressure"]},
]

ROGUE_TEMPLATE = {
    "ip": "192.168.20.66", "mac": "DE:AD:BE:EF:20:66", "hostname": "unknown-device", "vendor": "unknown",
    "model": "unknown", "device_type": "Unknown", "level": "2",
    "state": {"icmp": "ONLINE", "rtt_ms": 3.2, "snmp": None, "winrm": None, "ssh": None, "accounts": {},
              "identity": {"hostname": "unknown-device"}, "network": {"listening": [], "connections": []}},
}
