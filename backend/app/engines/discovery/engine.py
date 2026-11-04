"""Progressive discovery: ARP -> ICMP -> SNMP, merge by MAC, devices streamed via SSE (docs/STATE_MACHINES §1)."""

from __future__ import annotations

import asyncio
import ipaddress
import logging

from sqlalchemy import select

from app.adapters.base import Credential, DiscoveredHost, Protocol, Target
from app.context import AppContext
from app.core import audit, events
from app.core.audit import system
from app.core.clock import utcnow
from app.core.correlation import get_correlation_id
from app.engines.assessment.findings import open_event_finding
from app.engines.inventory import merge_observation, refresh_asset, upsert_fields
from app.models import Asset, DiscoveryJob, DiscoveryObservation, Zone
from app.workflow.machine import DISCOVERY
from app.workflow.steps import StepTracker

log = logging.getLogger("otprobe.discovery")
ACTOR = system("discovery-engine")
STEPS = ["VALIDATE", "ARP", "ICMP", "SNMP", "MERGE"]
POSITIVE_ICMP = {"ONLINE", "HIGH_LATENCY"}


def zones_for_targets(session, targets: list[str]) -> dict[str, Zone]:
    zones = list(session.scalars(select(Zone)))
    out = {}
    for t in targets:
        net = ipaddress.ip_network(t, strict=False)
        out[t] = next(z for z in zones if net.subnet_of(ipaddress.ip_network(z.cidr)))
    return out


def baseline_zone_ids(session, zones: list[Zone], exclude_job: str) -> set[str]:
    done = list(session.scalars(select(DiscoveryJob).where(DiscoveryJob.status == "COMPLETED",
                                                            DiscoveryJob.id != exclude_job)))
    out = set()
    for z in zones:
        znet = ipaddress.ip_network(z.cidr)
        if any(ipaddress.ip_network(t, strict=False).overlaps(znet) for j in done for t in j.targets):
            out.add(z.id)
    return out


class DiscoveryEngine:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx

    def _progress(self, job_id: str, progress: int, phase: str) -> None:
        with self.ctx.db.session() as s:
            job = s.get(DiscoveryJob, job_id)
            job.progress, job.phase = progress, phase
            events.stage(s, "discovery.progress", "discovery", job_id,
                         {"progress": progress, "phase": phase, "devicesFound": job.devices_found})

    async def run(self, job_id: str) -> None:
        db = self.ctx.db
        tracker = StepTracker(db, "DISCOVERY", job_id, "discovery")
        with db.session() as s:
            job = s.get(DiscoveryJob, job_id)
            DISCOVERY.transition(s, job, "RUNNING", ACTOR)
            job.started_at, job.phase = utcnow(), "VALIDATE"
            targets, methods = list(job.targets), list(job.methods)
        try:
            await self._run(job_id, targets, methods, tracker)
        except asyncio.CancelledError:
            with db.session() as s:
                job = s.get(DiscoveryJob, job_id)
                DISCOVERY.transition(s, job, "CANCELLED", ACTOR, "Cancelled by user")
                job.finished_at = utcnow()
            tracker.skip_remaining("Cancelled")
            raise
        except Exception as exc:  # noqa: BLE001 - any engine error fails the job, visibly
            log.exception("discovery %s failed", job_id)
            with db.session() as s:
                job = s.get(DiscoveryJob, job_id)
                DISCOVERY.transition(s, job, "FAILED", ACTOR, str(exc))
                job.error, job.finished_at = str(exc), utcnow()
            tracker.skip_remaining(f"Aborted: {exc}")

    async def _run(self, job_id: str, targets: list[str], methods: list[str], tracker: StepTracker) -> None:
        ctx, db = self.ctx, self.ctx.db
        tracker.plan(STEPS)
        tracker.start("VALIDATE", "Resolving targets against configured zones")
        with db.session() as s:
            zone_map = zones_for_targets(s, targets)
            baseline = baseline_zone_ids(s, list(zone_map.values()), job_id)
            safe_targets = [t for t, z in zone_map.items() if z.safe_mode]
        snmp_cred: Credential | None = None
        if "SNMP" in methods:
            snmp_cred = await ctx.vault.resolve("OT-SNMPV3-RO", purpose=f"discovery {job_id}",
                                                correlation_id=get_correlation_id())
        await ctx.pacer.sleep(0.3)
        detail = f"{len(targets)} target(s), methods {', '.join(methods)}"
        if safe_targets:
            detail += f". SAFE MODE for {', '.join(safe_targets)}: passive/read-only, rate-limited (Level 0/1)"
        tracker.ok("VALIDATE", detail, {"safeModeTargets": safe_targets, "baselineZones": sorted(baseline)})
        self._progress(job_id, 10, "ARP")

        tlist = [Target(t, credential=snmp_cred, safe_mode=zone_map[t].safe_mode, timeout_sec=1.0) for t in targets]
        seen: dict[str, set[str]] = {}   # asset_id -> methods with a positive response in this job

        # ARP: devices appear one by one
        if "ARP" in methods:
            tracker.start("ARP", "Reading ARP/neighbor tables (switch span)")
            arp = ctx.registry.get(Protocol.ARP)
            n = 0
            for t in tlist:
                async for host in arp.discover(t):
                    n += 1
                    self._on_arp(job_id, host, baseline, seen)
                    tracker.update("ARP", f"{n} host(s) answered ARP")
            tracker.ok("ARP", f"{n} host(s) answered ARP")
        else:
            tracker.skip("ARP", "Method not selected")
        self._progress(job_id, 30, "ICMP")

        if "ICMP" in methods:
            tracker.start("ICMP", "Echo sweep (rate-limited in safe mode)")
            icmp = ctx.registry.get(Protocol.ICMP)
            replies = blocked = 0
            for t in tlist:
                async for host in icmp.discover(t):
                    positive = host.data.get("reachability.icmp") in POSITIVE_ICMP
                    replies += positive
                    blocked += not positive
                    self._on_ip_only(job_id, host, positive, seen)
            tracker.ok("ICMP", f"{replies} echo repl{'y' if replies == 1 else 'ies'}, {blocked} filtered. "
                               "No ICMP reply does not mean a device is offline.")
        else:
            tracker.skip("ICMP", "Method not selected")
        self._progress(job_id, 60, "SNMP")

        if "SNMP" in methods:
            tracker.start("SNMP", "SNMPv3 GET sysName/sysDescr/entity (read-only profile OT-SNMPV3-RO)")
            snmp = ctx.registry.get(Protocol.SNMP)
            n = 0
            for t in tlist:
                async for host in snmp.discover(t):
                    n += 1
                    self._on_ip_only(job_id, host, True, seen)
            tracker.ok("SNMP", f"{n} SNMP agent(s) responded")
        else:
            tracker.skip("SNMP", "Method not selected")

        tracker.start("MERGE", "Reconciling inventory")
        with db.session() as s:
            missing = 0
            for asset in s.scalars(select(Asset)):
                in_scope = any(ipaddress.ip_address(asset.ip) in ipaddress.ip_network(t, strict=False)
                               for t in targets)
                if not in_scope:
                    continue
                if asset.id in seen:
                    asset.discovered_by = sorted(seen[asset.id])
                elif asset.status != "OFFLINE":
                    asset.status = "OFFLINE"
                    missing += 1
                    audit.record(s, ACTOR, "ASSET_UNREACHABLE", "asset", asset.id,
                                 {"ip": asset.ip, "message": "Device not observed by any discovery method"})
                    events.stage(s, "asset.updated", "asset", asset.id, {"status": "OFFLINE"})
            job = s.get(DiscoveryJob, job_id)
            job.devices_found = len(seen)
        tracker.ok("MERGE", f"{len(seen)} device(s) observed, {missing} not seen (marked OFFLINE)")
        self._progress(job_id, 100, "DONE")
        with db.session() as s:
            job = s.get(DiscoveryJob, job_id)
            DISCOVERY.transition(s, job, "COMPLETED", ACTOR, details={
                "devicesFound": job.devices_found, "newAssets": job.new_assets, "rogue": job.rogue_count})
            job.finished_at = utcnow()

    def _on_arp(self, job_id: str, host: DiscoveredHost, baseline: set[str], seen: dict[str, set[str]]) -> None:
        with self.ctx.db.session() as s:
            asset, created, rogue = merge_observation(s, host.ip, host.mac, ACTOR, baseline)
            if rogue:
                rule = next(r for r in self.ctx.rules.policies["network-hygiene"]["rules"]
                            if r["id"] == "NET-ROGUE-001")
                open_event_finding(s, asset.id, rule, {"ip": host.ip, "mac": host.mac, "authorized": False}, ACTOR)
            upsert_fields(s, asset.id, host.data, "ARP", "DISCOVERY", "DISCOVERY", job_id)
            s.add(DiscoveryObservation(job_id=job_id, asset_id=asset.id, ip=host.ip, mac=host.mac, method="ARP",
                                       responded=True, result=host.data))
            refresh_asset(s, asset, self.ctx.rules)
            seen.setdefault(asset.id, set()).add("ARP")
            asset.discovered_by = sorted(set(asset.discovered_by or []) | {"ARP"})
            job = s.get(DiscoveryJob, job_id)
            job.devices_found = len(seen)
            job.new_assets += created
            job.rogue_count += rogue
            events.stage(s, "discovery.device_found", "discovery", job_id,
                         {"assetId": asset.id, "ip": host.ip, "mac": host.mac, "method": "ARP", "new": created,
                          "rogue": rogue, "devicesFound": job.devices_found})

    def _on_ip_only(self, job_id: str, host: DiscoveredHost, positive: bool, seen: dict[str, set[str]]) -> None:
        method = host.method.value
        with self.ctx.db.session() as s:
            asset = s.scalar(select(Asset).where(Asset.ip == host.ip))
            s.add(DiscoveryObservation(job_id=job_id, asset_id=asset.id if asset else None, ip=host.ip, mac=None,
                                       method=method, responded=positive, result=host.data))
            if asset is None:
                return  # IP-only response, awaiting ARP (kept as observation)
            upsert_fields(s, asset.id, host.data, method, "DISCOVERY", "DISCOVERY", job_id)
            if positive:
                seen.setdefault(asset.id, set()).add(method)
                asset.discovered_by = sorted(set(asset.discovered_by or []) | {method})
                asset.status, asset.last_seen = "ONLINE", utcnow()
                job = s.get(DiscoveryJob, job_id)
                job.devices_found = len(seen)
            refresh_asset(s, asset, self.ctx.rules)
