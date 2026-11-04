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
from app.models import Asset, ProbeResult, ProbeRun, Zone
from app.workflow.machine import PROBE
from app.workflow.steps import StepTracker

log = logging.getLogger("otprobe.probe")
ACTOR = system("probe-engine")
STEPS = ["ICMP", "ARP", "WINRM", "WMI", "SNMP", "SSH", "MQTT", "COLLECT", "CLASSIFY", "EVALUATE"]
SAFE_MODE_SKIP = "Safe mode (Level 0/1): only passive/read-only methods are used"
WMI_GROUPS = ["os", "hardware", "firewall", "antivirus", "software", "services", "hotfixes", "network"]


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

    async def run(self, probe_id: str) -> None:
        db = self.ctx.db
        tracker = StepTracker(db, "PROBE", probe_id, "probe")
        with db.session() as s:
            run = s.get(ProbeRun, probe_id)
            PROBE.transition(s, run, "RUNNING", ACTOR)
            run.started_at = utcnow()
        tracker.plan(STEPS)
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
        else:
            tracker.fail("ICMP", f"{reach}: {res.error_detail}")

        # ARP
        tracker.start("ARP", f"Neighbor lookup for {ip}")
        res = record(await reg.get(Protocol.ARP).health_check(Target(ip, safe_mode=safe)))
        arp_up = res.ok
        if arp_up:
            seen_mac = res.data.get("network.mac")
            note = "" if seen_mac == mac else f" (WARNING: expected {mac})"
            tracker.ok("ARP", f"{ip} is-at {seen_mac}{note}")
        else:
            tracker.fail("ARP", res.error_detail or "No ARP entry")

        if not (icmp_up or arp_up):
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
        winrm = reg.get(Protocol.WINRM)
        tracker.start("WINRM", f"HTTPS {ip}:5986")
        if safe:
            tracker.skip("WINRM", SAFE_MODE_SKIP)
        else:
            hc = await winrm.health_check(Target(ip, port=5986))
            if not hc.ok:
                if known.get("services.winrm.available"):
                    record(hc)
                    failed.append("WINRM")
                    tracker.fail("WINRM", hc.error_detail or hc.status.value)
                else:
                    tracker.skip("WINRM", "TCP 5986 closed: WinRM not available on this device")
            else:
                cred = await ctx.vault.resolve("OT-WINDOWS-READONLY", purpose=f"agentless probe {probe_id}",
                                               correlation_id=cid)
                stages: list[dict[str, Any]] = []

                async def on_stage(st: Stage) -> None:
                    stages.append({"name": st.name, "status": st.status.value, "detail": st.detail})
                    tracker.update("WINRM", f"{st.name}: {st.detail}", data={"stages": list(stages)})

                res, session = await winrm.open_session(Target(ip, port=5986, credential=cred), on_stage)
                record(res)
                if session is not None:
                    tracker.ok("WINRM", f"Session created as {cred.username} (profile {cred.profile})",
                               {"stages": stages})
                else:
                    failed.append("WINRM")
                    tracker.fail("WINRM", res.error_detail or res.status.value, {"stages": stages})

        tracker.start("WMI", "CIM queries over WinRM")
        if session is None:
            tracker.skip("WMI", SAFE_MODE_SKIP if safe else "Requires a WinRM session")
        else:
            res = record(await reg.get(Protocol.WMI).probe(Target(ip, port=5986, credential=cred), Query(WMI_GROUPS)))
            await winrm.close_session(session)
            if res.ok:
                tracker.ok("WMI", f"Collected {', '.join(WMI_GROUPS)} ({len(res.data)} fields)")
            else:
                failed.append("WMI")
                tracker.fail("WMI", res.error_detail or res.status.value)

        # SNMP
        tracker.start("SNMP", "SNMPv3 GET (read-only profile OT-SNMPV3-RO)")
        snmp_cred = await ctx.vault.resolve("OT-SNMPV3-RO", purpose=f"agentless probe {probe_id}", correlation_id=cid)
        res = await reg.get(Protocol.SNMP).probe(Target(ip, credential=snmp_cred, safe_mode=safe, timeout_sec=2.0),
                                                 Query(["system", "interfaces", "entity", "lldp", "plc"]))
        if res.ok:
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
        else:
            tracker.skip("SNMP", "No SNMP agent responded")

        # SSH (stub)
        tracker.start("SSH", f"SSH {ip}:22")
        ssh = reg.get(Protocol.SSH)
        if safe:
            tracker.skip("SSH", SAFE_MODE_SKIP)
        else:
            hc = await ssh.health_check(Target(ip, port=22))
            if hc.status in (ResultStatus.REFUSED, ResultStatus.UNREACHABLE):
                tracker.skip("SSH", "TCP 22 closed: SSH not available on this device")
            else:
                ssh_cred = await ctx.vault.resolve("OT-LINUX-SSH-RO", purpose=f"agentless probe {probe_id}",
                                                   correlation_id=cid)
                res = record(await ssh.probe(Target(ip, port=22, credential=ssh_cred), Query(["identity"])))
                if res.ok:
                    tracker.ok("SSH", f"{res.data.get('os.product')} · kernel {res.data.get('os.kernel')}")
                else:
                    failed.append("SSH")
                    tracker.fail("SSH", res.error_detail or res.status.value)

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
