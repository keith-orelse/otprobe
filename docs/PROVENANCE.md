# Field provenance

Every stored fact about an asset is an `asset_fields` row:

```
asset_id · field_path · value · source · stage · collected_at · run_kind · run_id
```

- `source` ∈ `ARP`, `ICMP`, `SNMP`, `WinRM`, `WMI`, `SSH`, `MQTT`, `DEEP_AGENT`
- `stage` ∈ `DISCOVERY`, `AGENTLESS`, `DEEP`
- UQ(asset_id, field_path, source): each source keeps its latest value for a field, so the
  "Agentless vs Deep Agent" screen can show the values side by side.

## 1. Stages

| Stage | Produced by | Methods |
|---|---|---|
| `DISCOVERY` | Discovery job | ARP, ICMP, SNMP (sysName/sysDescr/sysObjectID/entity only) |
| `AGENTLESS` | Agentless probe | ICMP, ARP, WinRM, WMI/CIM, SNMP (full), SSH (stub), MQTT |
| `DEEP` | Deep assessment evidence from an enrolled agent | DEEP_AGENT |

## 2. Provenance matrix

`●` = collected at this stage · `◐` = partial / summary · blank = not available at this stage.

| Field group | Field paths (examples) | DISCOVERY | AGENTLESS | DEEP |
|---|---|---|---|---|
| Address | `network.ip`, `network.mac` | ● ARP | ● ARP | ● DEEP_AGENT (`network.interfaces[]`) |
| Reachability | `reachability.icmp`, `reachability.rtt_ms` | ● ICMP | ● ICMP | — (heartbeat replaces it) |
| SNMP identity | `snmp.sys_name`, `snmp.sys_descr`, `hardware.vendor`, `hardware.model` | ● SNMP (where SNMP works) | ● SNMP | |
| PLC identity | `firmware.version`, `plc.mode`, `plc.cpu` | ◐ SNMP (vendor/model) | ● SNMP | |
| Switch ports | `network.interfaces[]`, `network.active_ports`, `network.lldp_neighbors[]` | | ● SNMP | |
| Hostname | `identity.hostname` | | ● WMI / SNMP / SSH | ● DEEP_AGENT |
| OS | `os.name`, `os.product`, `os.version`, `os.build` | | ● WMI / SSH | ● DEEP_AGENT |
| Hardware | `hardware.manufacturer`, `hardware.cpu`, `hardware.ram_gb`, `hardware.disk[]`, `hardware.uptime_sec` | | ● WMI · ◐ SSH | ● DEEP_AGENT |
| Software | `software.installed[]` | | ◐ WMI (Uninstall keys only) | ● DEEP_AGENT (incl. per-user, Appx, versions, publishers) |
| Services | `services.running[]` | | ● WMI | ● DEEP_AGENT |
| Firewall | `firewall.state` | | ◐ WMI (on/off) | ● DEEP_AGENT (per-profile, rule count, default inbound action) |
| Antivirus | `antivirus.product`, `antivirus.state`, `antivirus.signature_age_days` | | ◐ WMI (product, state) | ● DEEP_AGENT |
| Patch status | `patches.installed[]`, `patches.missing[]`, `patches.missing_count` | | ◐ WMI (installed hotfixes only) | ● DEEP_AGENT (installed + missing) |
| Local admins | `local_admins.members[]` | | — *Not collected* | ● DEEP_AGENT |
| Password policy | `password_policy.*` | | — | ● DEEP_AGENT |
| Audit config | `audit.*` | | — | ● DEEP_AGENT |
| USB policy | `usb.storage_policy` | | — | ● DEEP_AGENT (may be missing → UNKNOWN) |
| Listening services | `network.listening[]` | | ◐ WMI (netstat summary) | ● DEEP_AGENT (with owning process) |
| MQTT | `mqtt.client_id`, `mqtt.topics[]`, `telemetry.kind` | | ● MQTT | |
| Agent health | `agent.health`, `agent.version` | | | ● DEEP_AGENT |
| Continuous monitoring / heartbeat | `agent.last_heartbeat_at` | | | ● (server side) |

Test-enforced rules that follow from the matrix:

- After discovery only: an asset has `network.ip`, `network.mac`, `reachability.*`, and `snmp.*`/vendor/model
  where SNMP responded. **No** `identity.hostname`, `os.*` or `software.*`. The asset table shows the Hostname cell
  as `—` with the tooltip "Run agentless probe". It shows `snmp.sys_name` in muted text, labelled `(sysName)`.
- Sensors after discovery: only `network.ip`, `network.mac` with source `ARP`. `reachability.icmp = BLOCKED`
  is stored with source `ICMP` (see note). There are no SNMP fields.

> **ICMP note shown in UI:** "No ICMP reply does not mean the device is offline. This device answered ARP."
> An asset's `status` is `ONLINE` if *any* method observed it in the last discovery or probe, not just ICMP.

## 3. Effective value

The `assets` columns and the asset page show the **effective** value for each field path:

1. Take the candidates from all sources for that `field_path`.
2. Pick the one with the newest `collected_at`.
3. On a tie, pick by stage rank (`DEEP` > `AGENTLESS` > `DISCOVERY`).

The UI always shows the winning `source · stage · collected_at` next to the value. The comparison screen shows the
AGENTLESS and DEEP candidates side by side, without choosing a winner.

## 4. Merge by MAC

```
for each observation in job (streamed):
  if obs.mac:
      asset = assets.find_by_mac(obs.mac)
      if asset is None:
          asset = create(mac, ip)                     → ASSET_CREATED
          if zone_has_baseline(obs.ip):               → is_rogue = true, finding NET-ROGUE-001, ROGUE_DEVICE_DETECTED
      elif asset.ip != obs.ip:                        → update ip, ASSET_IP_CHANGED
      if another asset holds obs.ip with a different MAC → IP_MAC_CONFLICT audit event (both kept)
  else:  # ICMP/SNMP observation without MAC
      asset = match by ip within this job's ARP results, else by current asset.ip
      if none: keep as discovery_observation only (UI: "IP-only response, awaiting ARP")
  upsert asset_fields(source=obs.method, stage=DISCOVERY)
  publish SSE discovery.device_found / asset.updated
```

- A zone **baseline** exists once a discovery job that covers the zone's CIDR has reached `COMPLETED`. The first
  discovery creates assets without rogue alerts. Each later discovery flags any unknown MAC.
- An admin can mark a rogue as authorised (`POST /assets/{id}/authorize`). This clears `is_rogue` and resolves
  `NET-ROGUE-001` with a reason.

## 5. Classification

Classification is data-driven (`rules/classification.yaml`). It uses weighted evidence signals over the
effective fields. `confidence = matched_weight / total_weight_for_type`, rounded to an integer percentage. The
type with the highest confidence wins. The evidence list is the set of matched signals.

Example for eng-ws-01 (acceptance B):

| Signal | Field / test | Weight | Matched |
|---|---|---|---|
| Windows OS | `os.name` contains `Windows`, product not `Server` | 30 | ✓ |
| WinRM available | `services.winrm.available == true` | 15 | ✓ |
| Engineering software detected | `software.installed[].name` matches `TIA Portal|Studio 5000|…` | 35 | ✓ |
| Hostname pattern | `identity.hostname` matches `^eng-?ws` | 15 | ✓ |
| OT protocol client | `network.connections[].remote_port` intersects 102/44818/502 | 5 | ✓ (WMI netstat shows S7comm to plc-01) |
| Dual-homed (L2 + L1 interfaces) | `network.interfaces` count ≥ 2 | 10 | — |

→ **Windows Engineering Workstation, 91%** (100 of 110), with 5 evidence items. A type is assigned only at ≥ 40%
confidence (`min_confidence`).

Eligibility (`rules/eligibility.yaml`) is evaluated after classification, using the type, OS family and
criticality. See [SIMULATED_NETWORK.md §2.3](SIMULATED_NETWORK.md#23-agent-eligibility-derived-by-otprobe-not-stored-in-the-simulator).
