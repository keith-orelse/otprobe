"""Agentless probe: ICMP -> ARP -> WinRM -> WMI -> SNMP -> SSH -> MQTT -> collect -> classify."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.adapters.base import AdapterResult, Protocol, Query, ResultStatus, Stage, Target
from app.context import AppContext
from app.core import audit, events
from app.core.audit import system
from app.core.clock import utcnow
from app.core.correlation import get_correlation_id
from app.engines.assessment.runner import evaluate_agentless
from app.engines.inventory import effective_fields, refresh_asset, upsert_fields
from app.engines.protocol_events import SNMP_EVENTS, winrm_event
from app.models import Asset, ProbeResult, ProbeRun, Zone
from app.workflow.machine import PROBE
from app.workflow.steps import StepTracker

log = logging.getLogger("otprobe.probe")
ACTOR = system("probe-engine")
STEPS = ["ICMP", "ARP", "WINRM", "WMI", "SNMP", "SSH", "MQTT", "COLLECT", "CLASSIFY", "EVALUATE"]
SAFE_MODE_SKIP = "Safe mode (Level 0/1): only passive/read-only methods are used"
WMI_GROUPS = ["os", "hardware", "firewall", "antivirus", "software", "services", "hotfixes", "network"]
SSH_GROUPS = ["identity", "packages", "services", "network", "firewall"]
OT_PROTOCOLS = {"modbus", "s7", "enip", "bacnet", "opcua"}   # plugin names that count as OT protocols


class ProbeEngine:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx

    def _save(self, probe_id: str, res: AdapterResult) -> None:
        with self.ctx.db.session() as s:
            s.add(ProbeResult(probe_run_id=probe_id, protocol=res.protocol.value, status=res.status.value,
                              data=res.data, raw=res.raw, latency_ms=res.latency_ms,
                              stages=[{"name": st.name, "status": st.status.value, "detail": st.detail,
                                       "at": st.at.isoformat() if st.at else None} for st in res.stages],
                              error_code=res.error_code, error_detail=res.error_detail,
                              collected_at=res.collected_at or utcnow()))

    async def _cred(self, profile: str, probe_id: str, cid: str):
        """The vault credential, or None when the profile does not exist (live installs start with an empty vault)."""
        try:
            return await self.ctx.vault.resolve(profile, purpose=f"agentless probe {probe_id}", correlation_id=cid)
        except KeyError:
            return None

    async def _ot_step(self, ip: str, open_ports: set[int], tracker: StepTracker, record) -> None:
        tracker.start("OT", "Read-only OT protocol identification")
        answered: list[str] = []
        parts: list[str] = []
        not_enabled: list[str] = []
        for plugin in self.ctx.registry.plugins():
            ports = [p for p in plugin.ports if p in open_ports]
            if plugin.ports and not ports:
                continue                                   # its port did not answer: nothing is sent
            res = await plugin.identify(Target(ip, port=ports[0] if ports else None, timeout_sec=3.0))
            if res.error_code == "PLUGIN_NOT_ENABLED":
                if plugin.ports:
                    not_enabled.append(plugin.display_label)
                continue
            record(res)
            if res.ok:
                answered.append(plugin.name)
                ident = " ".join(str(res.data[k]) for k in ("hardware.vendor", "hardware.model", "plc.product_code",
                                                              "http.title", "opcua.application_name")
                                 if res.data.get(k))
                parts.append(f"{plugin.display_label}: {ident or 'answered'}")
            else:
                parts.append(f"{plugin.display_label}: {res.error_detail or res.status.value}")
        ot = sorted(n for n in answered if n in OT_PROTOCOLS)
        if ot:
            record(AdapterResult(Protocol.OT, ip, ResultStatus.OK, {"ot.protocols": ot}, collected_at=utcnow(),
                                 latency_ms=0.0))
        if not_enabled:
            parts.append(f"not enabled for this range: {', '.join(not_enabled)}")
        if parts:
            tracker.ok("OT", "; ".join(parts))
        else:
            tracker.skip("OT", "No OT or web service port answered")

    async def _port(self, profile: str, default: int) -> int:
        """A profile's non-standard service port (params.port), read without retrieving the secret."""
        try:
            return (await self.ctx.vault.describe(profile)).port or default
        except KeyError:
            return default

    def _audit(self, asset_id: str, event: str, detail: str | None) -> None:
        with self.ctx.db.session() as s:
            audit.record(s, ACTOR, event, "asset", asset_id, {"message": detail})

    async def run(self, probe_id: str) -> None:
        db = self.ctx.db
        tracker = StepTracker(db, "PROBE", probe_id, "probe")
        with db.session() as s:
            run = s.get(ProbeRun, probe_id)
            PROBE.transition(s, run, "RUNNING", ACTOR)
            run.started_at = utcnow()
        steps = list(STEPS)
        if self.ctx.registry.has(Protocol.TCP):
            steps.insert(steps.index("ARP") + 1, "TCP")
        if self.ctx.registry.plugins():
            steps.insert(steps.index("SNMP") + 1, "OT")
        tracker.plan(steps)
        try:
            await self._run(probe_id, tracker)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.exception("probe %s failed", probe_id)
            with db.session() as s:
                run = s.get(ProbeRun, probe_id)
                PROBE.transition(s, run, "FAILED", ACTOR, str(exc))
                run.error, run.finished_at = str(exc), utcnow()
            tracker.skip_remaining(f"Aborted: {exc}")

    async def _run(self, probe_id: str, tracker: StepTracker) -> None:
        ctx, db = self.ctx, self.ctx.db
        reg = ctx.registry
        with db.session() as s:
            run = s.get(ProbeRun, probe_id)
            asset = s.get(Asset, run.asset_id)
            zone = s.get(Zone, asset.zone_id) if asset.zone_id else None
            known = {p: r.value for p, r in effective_fields(s, asset.id).items()}
            asset_id, ip, mac = asset.id, asset.ip, asset.mac
        safe = bool(zone and zone.safe_mode)
        cid = get_correlation_id()
        results: list[AdapterResult] = []
        failed: list[str] = []

        def record(res: AdapterResult) -> AdapterResult:
            results.append(res)
            self._save(probe_id, res)
            return res

        # ICMP
        tracker.start("ICMP", f"Echo request to {ip}")
        res = record(await reg.get(Protocol.ICMP).health_check(Target(ip, safe_mode=safe)))
        reach = res.data.get("reachability.icmp")
        icmp_up = reach in ("ONLINE", "HIGH_LATENCY")
        if icmp_up:
            tracker.ok("ICMP", f"{reach} · rtt {res.data.get('reachability.rtt_ms')} ms")
        elif reach == "BLOCKED":
            tracker.ok("ICMP", "BLOCKED: no ICMP reply. This does not mean the device is offline.")
            self._audit(asset_id, "ICMP_BLOCKED_OBSERVED", "No ICMP reply. This does not mean the device is offline.")
        else:
            tracker.fail("ICMP", f"{reach}: {res.error_detail}")

        # ARP
        tracker.start("ARP", f"Neighbor lookup for {ip}")
        res = record(await reg.get(Protocol.ARP).health_check(Target(ip, safe_mode=safe)))
        arp_up = res.ok
        if arp_up:
            seen_mac, via = res.data.get("network.mac"), res.data.get("network.arp_via")
            if via:
                tracker.ok("ARP", f"Answered by {via} (proxy ARP: the same MAC answers for {res.raw.get('sharedBy')} "
                                  "addresses), so this device's own MAC is not visible")
            else:
                note = f" (WARNING: expected {mac})" if mac and seen_mac != mac else ""
                tracker.ok("ARP", f"{ip} is-at {seen_mac}{note}")
        else:
            tracker.fail("ARP", res.error_detail or "No ARP entry")

        tcp_up = False
        open_ports = set(known.get("network.open_ports") or [])
        if reg.has(Protocol.TCP):
            tracker.start("TCP", "TCP connect to known service ports (no payload)")
            res = record(await reg.get(Protocol.TCP).probe(Target(ip, safe_mode=safe), Query([])))
            tcp_up = res.status in (ResultStatus.OK, ResultStatus.REFUSED)
            if tcp_up:
                open_ports = set(res.data.get("network.open_ports") or [])
            if res.ok:
                tracker.ok("TCP", f"Open ports: {', '.join(map(str, res.data.get('network.open_ports', [])))}")
            elif tcp_up:
                tracker.ok("TCP", "Host answered; every checked port is closed")
            else:
                tracker.fail("TCP", res.error_detail or res.status.value)

        if not (icmp_up or arp_up or tcp_up):
            tracker.skip_remaining("Device not reachable by ARP or ICMP")
            with db.session() as s:
                a = s.get(Asset, asset_id)
                a.status = "OFFLINE"
                audit.record(s, ACTOR, "ASSET_UNREACHABLE", "asset", asset_id,
                             {"ip": ip, "message": "Device not reachable by ARP or ICMP"})
                run = s.get(ProbeRun, probe_id)
                PROBE.transition(s, run, "FAILED", ACTOR, "Device not reachable by ARP or ICMP")
                run.error, run.finished_at = "Device not reachable by ARP or ICMP", utcnow()
                events.stage(s, "asset.updated", "asset", asset_id, {"status": "OFFLINE"})
            return

        # WinRM + WMI
        session = None
        winrm_options: dict[str, Any] = {}       # carries the pinned certificate from the session to WMI
        winrm = reg.get(Protocol.WINRM)
        winrm_port = await self._port("OT-WINDOWS-READONLY", 5986)
        tracker.start("WINRM", f"{'HTTP' if winrm_port == 5985 else 'HTTPS'} {ip}:{winrm_port}")
        if safe:
            tracker.skip("WINRM", SAFE_MODE_SKIP)
        else:
            hc = await winrm.health_check(Target(ip, port=winrm_port))
            cred = None if not hc.ok else await self._cred("OT-WINDOWS-READONLY", probe_id, cid)
            if hc.status == ResultStatus.NOT_SUPPORTED:
                tracker.skip("WINRM", hc.error_detail or "WinRM not available")
            elif hc.ok and cred is None:
                tracker.skip("WINRM", "No credential profile 'OT-WINDOWS-READONLY' in the vault")
            elif not hc.ok:
                if known.get("services.winrm.available"):
                    record(hc)
                    failed.append("WINRM")
                    tracker.fail("WINRM", hc.error_detail or hc.status.value)
                    self._audit(asset_id, winrm_event(hc.status), hc.error_detail)
                else:
                    tracker.skip("WINRM", f"TCP {winrm_port} closed: WinRM not available on this device"
                                 if hc.status == ResultStatus.REFUSED else
                                 f"TCP {winrm_port} not answering: no WinRM listener, or a firewall drops it")
            else:
                stages: list[dict[str, Any]] = []

                async def on_stage(st: Stage) -> None:
                    stages.append({"name": st.name, "status": st.status.value, "detail": st.detail})
                    tracker.update("WINRM", f"{st.name}: {st.detail}", data={"stages": list(stages)})

                cert_pin = known.get("services.winrm.cert_sha256")
                if cert_pin:
                    winrm_options = {"cert_sha256": cert_pin}
                res, session = await winrm.open_session(Target(ip, port=winrm_port, credential=cred,
                                                               options=winrm_options), on_stage)
                record(res)
                if not cert_pin and res.data.get("services.winrm.cert_sha256"):
                    winrm_options = {"cert_sha256": res.data["services.winrm.cert_sha256"]}
                    self._audit(asset_id, "WINRM_CERT_PINNED",
                                f"Trusted on first use: SHA-256 {res.data['services.winrm.cert_sha256']}")
                if session is not None:
                    tracker.ok("WINRM", f"Session created as {cred.username} (profile {cred.profile})",
                               {"stages": stages})
                else:
                    failed.append("WINRM")
                    tracker.fail("WINRM", res.error_detail or res.status.value, {"stages": stages})
                    self._audit(asset_id, "WINRM_CERT_CHANGED" if res.error_code == "CERT_CHANGED"
                                else winrm_event(res.status), res.error_detail)

        tracker.start("WMI", "CIM queries over WinRM")
        if session is None:
            tracker.skip("WMI", SAFE_MODE_SKIP if safe else "Requires a WinRM session")
        else:
            res = record(await reg.get(Protocol.WMI).probe(Target(ip, port=winrm_port, credential=cred,
                                                                  options=winrm_options), Query(WMI_GROUPS)))
            await winrm.close_session(session)
            if res.ok:
                tracker.ok("WMI", f"Collected {', '.join(WMI_GROUPS)} ({len(res.data)} fields)")
            else:
                failed.append("WMI")
                tracker.fail("WMI", res.error_detail or res.status.value)

        # SNMP
        tracker.start("SNMP", "SNMPv3 GET (read-only profile OT-SNMPV3-RO)")
        snmp_cred = await self._cred("OT-SNMPV3-RO", probe_id, cid)
        res = None if snmp_cred is None else await reg.get(Protocol.SNMP).probe(
            Target(ip, credential=snmp_cred, safe_mode=safe, timeout_sec=2.0),
            Query(["system", "interfaces", "entity", "lldp", "plc"]))
        if res is None:
            tracker.skip("SNMP", "No credential profile 'OT-SNMPV3-RO' in the vault")
        elif res.ok:
            record(res)
            parts = [f"sysName {res.data.get('snmp.sys_name')}"]
            if "network.active_ports" in res.data:
                parts.append(f"{len(res.data.get('network.interfaces', []))} interfaces, "
                             f"{res.data['network.active_ports']} active")
            if "plc.mode" in res.data:
                parts.append(f"mode {res.data['plc.mode']}, firmware {res.data.get('firmware.version')}")
            tracker.ok("SNMP", "; ".join(parts))
        elif known.get("snmp.sys_name"):
            record(res)
            failed.append("SNMP")
            tracker.fail("SNMP", f"{res.error_detail}. Identity fields not refreshed")
            self._audit(asset_id, SNMP_EVENTS.get(res.status, "SNMP_ERROR"), res.error_detail)
        else:
            tracker.skip("SNMP", "No SNMP agent responded")

        # OT identification plugins: read-only, one short session each; the gate decides per range
        if reg.plugins():
            await self._ot_step(ip, open_ports, tracker, record)

        # SSH
        ssh_port = await self._port("OT-LINUX-SSH-RO", 22)
        tracker.start("SSH", f"SSH {ip}:{ssh_port}")
        ssh = reg.get(Protocol.SSH)
        if safe:
            tracker.skip("SSH", SAFE_MODE_SKIP)
        else:
            hc = await ssh.health_check(Target(ip, port=ssh_port))
            ssh_cred = None
            if hc.status == ResultStatus.NOT_SUPPORTED:
                tracker.skip("SSH", hc.error_detail or "SSH not available")
            elif hc.status in (ResultStatus.REFUSED, ResultStatus.UNREACHABLE):
                tracker.skip("SSH", f"TCP {ssh_port} closed: SSH not available on this device"
                             if hc.status == ResultStatus.REFUSED else
                             f"TCP {ssh_port} not answering: no SSH server, or a firewall drops it")
            elif (ssh_cred := await self._cred("OT-LINUX-SSH-RO", probe_id, cid)) is None:
                tracker.skip("SSH", "No credential profile 'OT-LINUX-SSH-RO' in the vault")
            else:
                if "services.ssh.banner" in hc.data:
                    record(hc)
                pinned = known.get("ssh.host_key")
                res = record(await ssh.probe(Target(ip, port=ssh_port, credential=ssh_cred,
                                                    options={"host_key": pinned} if pinned else {}),
                                             Query(SSH_GROUPS)))
                if res.ok:
                    if not pinned and res.data.get("ssh.host_key"):
                        self._audit(asset_id, "SSH_HOST_KEY_PINNED",
                                    f"Trusted on first use: {res.data['ssh.host_key']}")
                    os_name = res.data.get("os.name") or res.data.get("os.product")
                    detail = f"{os_name} · kernel {res.data.get('os.kernel')}"
                    if "software.installed" in res.data:
                        detail += f" · {len(res.data['software.installed'])} packages"
                    if res.status == ResultStatus.PARTIAL:
                        detail += f" ({res.error_detail})"
                    tracker.ok("SSH", detail)
                else:
                    failed.append("SSH")
                    tracker.fail("SSH", res.error_detail or res.status.value)
                    if res.error_code == "HOST_KEY_CHANGED":
                        self._audit(asset_id, "SSH_HOST_KEY_CHANGED", res.error_detail)

        # MQTT
        tracker.start("MQTT", "Broker client lookup")
        res = await reg.get(Protocol.MQTT).probe(Target(ip), Query(["clients"]))
        if res.ok:
            record(res)
            tracker.ok("MQTT", f"client {res.data['mqtt.client_id']} publishes {', '.join(res.data['mqtt.topics'])}")
        else:
            tracker.skip("MQTT", res.error_detail or "No MQTT client")

        # Collect
        tracker.start("COLLECT", "Persisting fields with provenance")
        with db.session() as s:
            n = 0
            for r in results:
                n += upsert_fields(s, asset_id, r.data, r.protocol.value, "AGENTLESS", "PROBE", probe_id,
                                   r.collected_at)
            a = s.get(Asset, asset_id)
            a.status, a.last_seen, a.last_probe_at = "ONLINE", utcnow(), utcnow()
        tracker.ok("COLLECT", f"{n} field values stored (stage AGENTLESS)")

        # Classify
        tracker.start("CLASSIFY", "Evaluating classification signals and eligibility")
        with db.session() as s:
            a = s.get(Asset, asset_id)
            cls = refresh_asset(s, a, ctx.rules)
            run = s.get(ProbeRun, probe_id)
            run.classification, run.eligibility, run.eligibility_reason = cls, a.eligibility, a.eligibility_reason
            audit.record(s, ACTOR, "ASSET_CLASSIFIED", "asset", asset_id,
                         {"type": a.device_type, "confidence": (cls or {}).get("confidence"),
                          "eligibility": a.eligibility, "probeId": probe_id})
            label = f"{a.device_type} ({cls['confidence']}%)" if cls else "Unclassified"
        tracker.ok("CLASSIFY", f"{label} · agent eligibility {a.eligibility}")

        tracker.start("EVALUATE", "Evaluating compliance rules that accept agentless evidence")
        with db.session() as s:
            runs = evaluate_agentless(s, s.get(Asset, asset_id), probe_id, ACTOR)
            summary = "; ".join(f"{r.policy_key}: {r.counts.get('pass', 0)} pass, {r.counts.get('fail', 0)} fail, "
                                f"{r.counts.get('warning', 0)} warning, {r.counts.get('unknown', 0)} unknown"
                                for r in runs)
        if runs:
            tracker.ok("EVALUATE", f"{summary} (source AGENTLESS)")
        else:
            tracker.skip("EVALUATE", "No compliance policy applies to this device")

        with db.session() as s:
            run = s.get(ProbeRun, probe_id)
            status = "PARTIAL" if failed else "COMPLETED"
            PROBE.transition(s, run, status, ACTOR,
                             f"Failed protocols: {', '.join(failed)}" if failed else None)
            run.finished_at = utcnow()
            if failed:
                run.error = f"Failed protocols: {', '.join(failed)}"
