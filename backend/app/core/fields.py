"""Registry of provenance field paths (docs/PROVENANCE.md). Adapters may only emit these keys (contract C-04)."""

from __future__ import annotations

GROUPS: dict[str, list[str]] = {
    "Identity": ["identity.hostname", "identity.domain", "identity.fqdn", "snmp.sys_name", "snmp.sys_descr",
                 "snmp.sys_object_id", "hardware.vendor", "hardware.model", "hardware.serial", "plc.name",
                 "plc.product_code", "http.title", "http.server", "opcua.application_name", "opcua.product_uri"],
    "Network": ["network.ip", "network.mac", "reachability.icmp", "reachability.rtt_ms", "network.interfaces",
                "network.active_ports", "network.lldp_neighbors", "network.listening", "network.connections",
                "network.open_ports", "network.arp_via", "ot.protocols", "ot.device_type", "opcua.security_policies",
                "mqtt.client_id", "mqtt.topics", "mqtt.broker"],
    "Hardware": ["hardware.manufacturer", "hardware.cpu", "hardware.ram_gb", "hardware.disk",
                 "hardware.arch", "hardware.uptime_sec", "snmp.uptime_sec"],
    "OS": ["os.family", "os.name", "os.product", "os.version", "os.build", "os.kernel", "firmware.version",
           "plc.mode", "plc.cpu"],
    "Software": ["software.installed"],
    "Services": ["services.running", "services.winrm.available", "services.winrm.port", "services.winrm.tls",
                 "services.ssh.available", "services.ssh.banner", "ssh.host_key", "services.snmp.available"],
    "Firewall": ["firewall.state", "firewall.profiles", "firewall.default_inbound", "firewall.rule_count"],
    "Antivirus": ["antivirus.product", "antivirus.state", "antivirus.signature_age_days", "antivirus.realtime"],
    "Patch status": ["patches.installed", "patches.missing", "patches.missing_count"],
    "Security policy": ["local_admins.members", "local_admins.enabled_count", "password_policy.min_length",
                        "password_policy.complexity", "password_policy.lockout_threshold",
                        "password_policy.max_age_days", "audit.logon_events", "audit.process_creation",
                        "usb.storage_policy"],
    "Telemetry": ["telemetry.kind"],
    "Agent": ["agent.health", "agent.version", "agent.uptime_sec"],
}

PROVENANCE_FIELDS: frozenset[str] = frozenset(p for paths in GROUPS.values() for p in paths)
GROUP_OF: dict[str, str] = {p: g for g, paths in GROUPS.items() for p in paths}

SOURCES = ("ARP", "ICMP", "TCP", "SNMP", "WinRM", "WMI", "SSH", "MQTT", "Modbus", "S7", "EtherNet/IP", "BACnet",
           "OPC UA", "HTTP", "OT", "DEEP_AGENT")
STAGES = ("DISCOVERY", "AGENTLESS", "DEEP")
STAGE_RANK = {"DISCOVERY": 0, "AGENTLESS": 1, "DEEP": 2}
