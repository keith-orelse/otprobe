"""Precheck and agent deployment (docs/STATE_MACHINES.md §2). The engine reaches the host only through the
WinRM adapter and the PackageTransfer port; the agent then runs on its own and enrolls outbound."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import Any

from sqlalchemy import select

from app.adapters.base import PackageRef, Protocol, RemoteOperation, RemoteSession, Stage, Target
from app.context import AppContext
from app.core import audit, events
from app.core.audit import system
from app.core.clock import utcnow
from app.core.correlation import get_correlation_id
from app.core.security import opaque_token
from app.engines.inventory import effective_fields
from app.models import Agent, Asset, Deployment, EnrollmentToken, Package, PrecheckResult
from app.workflow.machine import AGENT, DEPLOYMENT
from app.workflow.steps import StepTracker

log = logging.getLogger("otprobe.deployment")
ACTOR = system("deployment-engine")
PRECHECKS = ["REACHABLE", "HOSTNAME_VERIFIED", "WINRM_AVAILABLE", "AUTHENTICATION", "PACKAGE_COMPATIBLE",
             "DISK_SPACE", "EXISTING_AGENT", "SERVER_CONNECTIVITY", "REBOOT_REQUIRED"]
DEPLOY_STEPS = ["CONNECT", "WINRM_SESSION", "RETRIEVE_CREDENTIAL", "TRANSFER_PACKAGE", "VERIFY_HASH", "INSTALL",
                "SERVICE_CREATED", "START_SERVICE", "AWAIT_ENROLLMENT"]
MIN_FREE_GB = 2
NEEDS_SESSION = "Requires an authenticated WinRM session"


def package_compatible(package: Package, os_product: str | None) -> tuple[bool, str]:
    if package.status != "ACTIVE":
        return False, f"Package {package.version} is {package.status}"
    if not os_product:
        return False, "OS unknown: run an agentless probe first"
    match = next((s for s in package.supported_os if os_product.startswith(s)), None)
    if match is None:
        return False, f"{os_product} not in supported OS list ({', '.join(package.supported_os)})"
    return True, f"{package.name} {package.version} ({package.architecture}) supports {os_product}"


class DeploymentEngine:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx

    # ------------------------------------------------------------------ precheck
    async def precheck(self, dep_id: str) -> None:
        try:
            await self._precheck(dep_id)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.exception("precheck %s crashed", dep_id)
            with self.ctx.db.session() as s:
                dep = s.get(Deployment, dep_id)
                DEPLOYMENT.transition(s, dep, "PRECHECK_FAILED", ACTOR, f"Precheck error: {exc}")

    async def _precheck(self, dep_id: str) -> None:
        ctx, reg = self.ctx, self.ctx.registry
        with ctx.db.session() as s:
            dep = s.get(Deployment, dep_id)
            asset = s.get(Asset, dep.asset_id)
            package = s.get(Package, dep.package_id)
            fields = {p: r.value for p, r in effective_fields(s, asset.id).items()}
            run_no, ip, hostname, profile = dep.precheck_run_no, asset.ip, asset.hostname, dep.credential_profile
            s.expunge(package)
        results: dict[str, tuple[str, str]] = {}

        def record(check: str, status: str, detail: str) -> None:
            results[check] = (status, detail)
            with ctx.db.session() as s:
                s.add(PrecheckResult(deployment_id=dep_id, run_no=run_no, seq=PRECHECKS.index(check) + 1,
                                     check=check, status=status, detail=detail))
                events.stage(s, "deployment.precheck", "deployment", dep_id,
                             {"runNo": run_no, "check": check, "status": status, "detail": detail})

        icmp = await reg.get(Protocol.ICMP).health_check(Target(ip))
        arp = await reg.get(Protocol.ARP).health_check(Target(ip))
        reach = icmp.data.get("reachability.icmp")
        if arp.ok or reach in ("ONLINE", "HIGH_LATENCY"):
            record("REACHABLE", "PASS", f"ARP {'ok' if arp.ok else 'no entry'}, ICMP {reach}")
        else:
            record("REACHABLE", "FAIL", "Device not reachable by ARP or ICMP")

        winrm = reg.get(Protocol.WINRM)
        hc = await winrm.health_check(Target(ip, port=5986))
        record("WINRM_AVAILABLE", "PASS" if hc.ok else "FAIL",
               f"HTTPS listener on {ip}:5986" if hc.ok else (hc.error_detail or hc.status.value))

        session: RemoteSession | None = None
        if hc.ok:
            cred = await ctx.vault.resolve(profile, purpose=f"precheck {dep_id}", correlation_id=get_correlation_id())
            res, session = await winrm.open_session(Target(ip, port=5986, credential=cred))
            record("AUTHENTICATION", "PASS" if session else "FAIL",
                   f"Authenticated as {cred.username} (profile {profile})" if session else res.error_detail or "")
        else:
            record("AUTHENTICATION", "FAIL", "WinRM not available")

        ok, detail = package_compatible(package, fields.get("os.product"))
        record("PACKAGE_COMPATIBLE", "PASS" if ok else "FAIL", detail)

        if session is None:
            for check in ("HOSTNAME_VERIFIED", "DISK_SPACE", "EXISTING_AGENT", "SERVER_CONNECTIVITY",
                          "REBOOT_REQUIRED"):
                record(check, "FAIL", NEEDS_SESSION)
        else:
            try:
                r = await winrm.execute(session, RemoteOperation.QUERY_HOSTNAME, {})
                remote = r.data.get("identity.hostname")
                mismatch = "" if remote == hostname else f" does not match inventory {hostname}"
                record("HOSTNAME_VERIFIED", "FAIL" if mismatch else "PASS", f"Remote hostname {remote}{mismatch}")
                r = await winrm.execute(session, RemoteOperation.QUERY_DISK_FREE, {})
                sysdrive = next((d for d in r.data.get("hardware.disk", []) if d["drive"] == "C:"), None)
                free = sysdrive["free_gb"] if sysdrive else 0
                record("DISK_SPACE", "PASS" if free >= MIN_FREE_GB else "FAIL",
                       f"{free} GB free on C: (required {MIN_FREE_GB} GB)")
                r = await winrm.execute(session, RemoteOperation.QUERY_AGENT_INSTALLED, {})
                installed = r.raw.get("installed")
                record("EXISTING_AGENT", "FAIL" if installed else "PASS",
                       f"Probe Agent {r.raw.get('version')} already installed" if installed else "No agent installed")
                r = await winrm.execute(session, RemoteOperation.QUERY_SERVER_CONNECTIVITY,
                                        {"server": ctx.settings.agent_server_url})
                record("SERVER_CONNECTIVITY", "PASS" if r.ok else "FAIL",
                       "Host can reach OTProbe server :443 through fw-conduit-01 (outbound only)" if r.ok
                       else r.error_detail or "")
                r = await winrm.execute(session, RemoteOperation.QUERY_REBOOT_PENDING, {})
                pending = r.raw.get("reboot_pending")
                record("REBOOT_REQUIRED", "WARN" if pending else "PASS",
                       "A reboot is pending; schedule within the maintenance window" if pending
                       else "No reboot pending; agent install does not require a reboot")
            finally:
                await winrm.close_session(session)

        failed = [c for c, (st, _) in results.items() if st == "FAIL"]
        with ctx.db.session() as s:
            dep = s.get(Deployment, dep_id)
            if failed:
                DEPLOYMENT.transition(s, dep, "PRECHECK_FAILED", ACTOR, f"Failed checks: {', '.join(failed)}",
                                      {"runNo": run_no})
            else:
                dep.precheck_passed_at = utcnow()
                DEPLOYMENT.transition(s, dep, "PRECHECK_PASSED", ACTOR, details={"runNo": run_no})

    # ------------------------------------------------------------------ deploy
    async def deploy(self, dep_id: str) -> None:
        tracker = StepTracker(self.ctx.db, "DEPLOY", dep_id, "deployment")
        tracker.plan(DEPLOY_STEPS)
        try:
            await self._deploy(dep_id, tracker)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.exception("deployment %s crashed", dep_id)
            self._fail(dep_id, tracker, None, "ENGINE_ERROR", str(exc))

    def _fail(self, dep_id: str, tracker: StepTracker, step: str | None, code: str, detail: str,
              event: str | None = None) -> None:
        if step:
            tracker.fail(step, detail)
        tracker.skip_remaining(f"Not run: {step or 'engine'} failed")
        with self.ctx.db.session() as s:
            dep = s.get(Deployment, dep_id)
            dep.failure_code, dep.failure_detail, dep.finished_at = code, detail, utcnow()
            for tok in s.scalars(select(EnrollmentToken).where(EnrollmentToken.deployment_id == dep_id,
                                                               EnrollmentToken.used_at.is_(None),
                                                               EnrollmentToken.revoked_at.is_(None))):
                tok.revoked_at = utcnow()
            if event:
                audit.record(s, ACTOR, event, "deployment", dep_id, {"code": code, "message": detail})
            DEPLOYMENT.transition(s, dep, "FAILED", ACTOR, detail, {"failureCode": code, "step": step})

    async def _deploy(self, dep_id: str, tracker: StepTracker) -> None:
        ctx, reg = self.ctx, self.ctx.registry
        with ctx.db.session() as s:
            dep = s.get(Deployment, dep_id)
            asset = s.get(Asset, dep.asset_id)
            pkg = s.get(Package, dep.package_id)
            ip, asset_id, profile = asset.ip, asset.id, dep.credential_profile
            ref = PackageRef(pkg.id, pkg.name, pkg.version, pkg.sha256, pkg.size_bytes)
        winrm = reg.get(Protocol.WINRM)

        tracker.start("CONNECT", f"Connecting to {ip}:5986")
        hc = await winrm.health_check(Target(ip, port=5986))
        if not hc.ok:
            return self._fail(dep_id, tracker, "CONNECT", "CONNECT_FAILED", hc.error_detail or hc.status.value,
                              f"WINRM_{hc.status.value}")
        tracker.ok("CONNECT", f"TCP {ip}:5986 reachable through fw-conduit-01")

        tracker.start("WINRM_SESSION", "Opening WinRM session")
        cred = await ctx.vault.resolve(profile, purpose=f"deployment {dep_id}", correlation_id=get_correlation_id())
        stages: list[dict[str, Any]] = []

        async def on_stage(st: Stage) -> None:
            stages.append({"name": st.name, "status": st.status.value, "detail": st.detail})
            tracker.update("WINRM_SESSION", f"{st.name}: {st.detail}", data={"stages": list(stages)})

        res, session = await winrm.open_session(Target(ip, port=5986, credential=cred), on_stage)
        if session is None:
            return self._fail(dep_id, tracker, "WINRM_SESSION", f"WINRM_{res.status.value}",
                              res.error_detail or res.status.value, f"WINRM_{res.status.value}")
        tracker.ok("WINRM_SESSION", f"Session created as {cred.username} (vault profile {profile})", {"stages": stages})

        try:
            await self._install(dep_id, tracker, winrm, session, ref, asset_id)
        finally:
            await winrm.close_session(session)

    async def _install(self, dep_id: str, tracker: StepTracker, winrm, session: RemoteSession, ref: PackageRef,
                       asset_id: str) -> None:
        ctx = self.ctx
        tracker.start("RETRIEVE_CREDENTIAL", "Minting the agent's single-use enrollment credential")
        token, token_hash = opaque_token("enr")
        ttl = ctx.settings.enrollment_token_ttl_sec
        with ctx.db.session() as s:
            tok = EnrollmentToken(token_hash=token_hash, asset_id=asset_id, deployment_id=dep_id,
                                  expires_at=utcnow() + timedelta(seconds=ttl))
            s.add(tok)
            s.flush()
            audit.record(s, ACTOR, "ENROLLMENT_TOKEN_ISSUED", "deployment", dep_id,
                         {"tokenId": tok.id, "expiresAt": tok.expires_at.isoformat(), "assetId": asset_id})
        tracker.ok("RETRIEVE_CREDENTIAL",
                   f"Enrollment token issued: single-use, {int(ttl // 60)} min TTL, stored hashed, "
                   "bound to asset + deployment")

        tracker.start("TRANSFER_PACKAGE", f"Copying {ref.name} {ref.version} ({ref.size_bytes / 1_048_576:.1f} MB)")

        async def progress(p: float) -> None:
            done = ref.size_bytes * p / 1_048_576
            tracker.update("TRANSFER_PACKAGE", f"Transferred {done:.1f} of {ref.size_bytes / 1_048_576:.1f} MB",
                           progress=round(p, 2))

        xfer = await ctx.transfer.transfer(session, ref, progress)
        if xfer.remote_path is None:
            return self._fail(dep_id, tracker, "TRANSFER_PACKAGE", xfer.error_code or "TRANSFER_FAILED",
                              xfer.error_detail or "Transfer failed", "DEPLOY_TRANSFER_FAIL")
        tracker.ok("TRANSFER_PACKAGE", f"{ref.size_bytes / 1_048_576:.1f} MB staged at {xfer.remote_path}")
        with ctx.db.session() as s:
            audit.record(s, ACTOR, "PACKAGE_TRANSFERRED", "deployment", dep_id,
                         {"package": ref.package_id, "path": xfer.remote_path, "bytes": xfer.bytes_transferred})

        cleanup = {"paths": [xfer.remote_path]}
        tracker.start("VERIFY_HASH", "Get-FileHash -Algorithm SHA256")
        r = await winrm.execute(session, RemoteOperation.VERIFY_FILE_HASH, {"path": xfer.remote_path,
                                                                             "sha256": ref.sha256})
        if not r.ok:
            await winrm.execute(session, RemoteOperation.REMOVE_FILES, cleanup)
            return self._fail(dep_id, tracker, "VERIFY_HASH", "HASH_MISMATCH" if r.error_code == "HASH_MISMATCH"
                              else r.error_code or "VERIFY_FAILED", r.error_detail or "Hash verification failed",
                              "DEPLOY_HASH_FAIL")
        tracker.ok("VERIFY_HASH", f"SHA-256 matches repository ({ref.sha256[:12]}…)")

        tracker.start("INSTALL", f"msiexec /i ProbeAgent-{ref.version}-x64.msi /qn")
        r = await winrm.execute(session, RemoteOperation.INSTALL_AGENT, {
            "version": ref.version, "path": xfer.remote_path, "enrollment_token": token, "deployment_id": dep_id,
            "server_url": ctx.settings.agent_server_url, "by": "OT-WINDOWS-INSTALLER"})
        if not r.ok:
            await winrm.execute(session, RemoteOperation.REMOVE_FILES, cleanup)
            return self._fail(dep_id, tracker, "INSTALL", r.error_code or "INSTALL_FAILED",
                              r.error_detail or "Install failed", "DEPLOY_INSTALL_FAIL")
        with ctx.db.session() as s:
            agent = Agent(asset_id=asset_id, deployment_id=dep_id, version=ref.version)
            AGENT.create(s, agent, ACTOR, {"deploymentId": dep_id, "version": ref.version})
            asset = s.get(Asset, asset_id)
            asset.agent_state, asset.current_agent_id = "ENROLLING", agent.id
            s.get(Deployment, dep_id).agent_id = agent.id
            events.stage(s, "asset.updated", "asset", asset_id, {"agentState": "ENROLLING"})
        tracker.ok("INSTALL", f"Installed to {r.raw.get('path')} (exit code 0); enrollment bundle written")

        tracker.start("SERVICE_CREATED", "Querying service OTProbeAgent")
        r = await winrm.execute(session, RemoteOperation.QUERY_SERVICE, {"name": "OTProbeAgent"})
        svc = r.raw.get("service")
        if not svc:
            return self._fail(dep_id, tracker, "SERVICE_CREATED", "SERVICE_MISSING", "Service OTProbeAgent not found",
                              "DEPLOY_INSTALL_FAIL")
        tracker.ok("SERVICE_CREATED", f"Service {svc['name']} created (start type {svc['start_type']})")

        tracker.start("START_SERVICE", "Start-Service OTProbeAgent")
        r = await winrm.execute(session, RemoteOperation.START_SERVICE, {"name": "OTProbeAgent"})
        if not r.ok:
            return self._fail(dep_id, tracker, "START_SERVICE", "SERVICE_START_FAILED", r.error_detail or "",
                              "DEPLOY_INSTALL_FAIL")
        await winrm.execute(session, RemoteOperation.REMOVE_FILES, cleanup)
        tracker.ok("START_SERVICE", "Service running; staging files removed")

        tracker.start("AWAIT_ENROLLMENT",
                      "Waiting for the agent to enroll and send its first heartbeat (outbound only)")
        with ctx.db.session() as s:
            dep = s.get(Deployment, dep_id)
            dep.enrolling_since = utcnow()
            DEPLOYMENT.transition(s, dep, "ENROLLING", ACTOR, details={"agentId": dep.agent_id})
