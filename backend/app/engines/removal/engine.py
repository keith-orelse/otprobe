"""Agent removal / rollback (docs/STATE_MACHINES.md §4). Never deletes history. If any step fails, the agent's
identity is revoked anyway (compensation) so a half-removed agent can never keep talking to the server."""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select

from app.adapters.base import Protocol, RemoteOperation, RemoteSession, Target
from app.context import AppContext
from app.core import audit, events
from app.core.audit import system
from app.core.clock import utcnow
from app.core.correlation import get_correlation_id
from app.models import Agent, AgentTask, AssessmentRun, Asset, Removal
from app.workflow.machine import AGENT, ASSESSMENT, REMOVAL, TASK
from app.workflow.steps import StepTracker

log = logging.getLogger("otprobe.removal")
ACTOR = system("removal-engine")
STEPS = ["STOP_ASSESSMENTS", "CONNECT", "STOP_AGENT", "UNINSTALL", "REVOKE_IDENTITY", "REMOVE_TEMP_FILES",
         "VALIDATE_DEVICE", "ROLLBACK_COMPLETED"]
STAGING = "C:/ProgramData/OTProbe/staging"


class StepFailed(Exception):
    def __init__(self, step: str, code: str, detail: str) -> None:
        super().__init__(detail)
        self.step, self.code, self.detail = step, code, detail


def revoke_agent(session, agent: Agent, actor, reason: str) -> bool:
    if agent.revoked_at is not None:
        return False
    agent.revoked_at = utcnow()
    audit.record(session, actor, "AGENT_CREDENTIAL_REVOKED", "agent", agent.id,
                 {"reason": reason, "credentialPrefix": agent.credential_prefix})
    return True


class RemovalEngine:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx

    async def run(self, removal_id: str, retry: bool = False) -> None:
        tracker = StepTracker(self.ctx.db, "REMOVAL", removal_id, "removal")
        if retry:
            from app.models import WorkflowStep
            with self.ctx.db.session() as s:
                for st in s.scalars(select(WorkflowStep).where(WorkflowStep.workflow_id == removal_id)):
                    st.status, st.detail, st.started_at, st.finished_at = "PENDING", "", None, None
        else:
            tracker.plan(STEPS)
        try:
            await self._run(removal_id, tracker)
        except StepFailed as f:
            self._fail(removal_id, tracker, f)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.exception("removal %s crashed", removal_id)
            self._fail(removal_id, tracker, StepFailed("ROLLBACK_COMPLETED", "ENGINE_ERROR", str(exc)))

    def _fail(self, removal_id: str, tracker: StepTracker, f: StepFailed) -> None:
        tracker.fail(f.step, f.detail)
        with self.ctx.db.session() as s:
            rem = s.get(Removal, removal_id)
            agent = s.get(Agent, rem.agent_id)
            revoked = revoke_agent(s, agent, ACTOR, f"Compensation after failed {f.step}")
            rem.failure_code, rem.failure_detail, rem.finished_at = f.code, f.detail, utcnow()
            REMOVAL.transition(s, rem, "FAILED", ACTOR, f.detail,     # audit event ROLLBACK_FAILED
                               {"failureCode": f.code, "step": f.step, "message": f.detail})
            if agent.status == "REMOVING":
                AGENT.transition(s, agent, "ERROR", ACTOR, f.detail)
            s.get(Asset, agent.asset_id).agent_state = agent.status
            events.stage(s, "asset.updated", "asset", agent.asset_id, {"agentState": agent.status})
        if revoked:
            tracker.ok("REVOKE_IDENTITY", "Agent identity revoked as a safety compensation")
        tracker.skip_remaining(f"Not run: {f.step} failed")

    async def _run(self, removal_id: str, tracker: StepTracker) -> None:
        ctx, db = self.ctx, self.ctx.db
        with db.session() as s:
            rem = s.get(Removal, removal_id)
            agent = s.get(Agent, rem.agent_id)
            asset = s.get(Asset, rem.asset_id)
            ip, agent_id, asset_id = asset.ip, agent.id, asset.id

        tracker.start("STOP_ASSESSMENTS", "Cancelling queued and running assessment tasks")
        with db.session() as s:
            cancelled = 0
            for task in s.scalars(select(AgentTask).where(AgentTask.agent_id == agent_id,
                                                          AgentTask.status.in_(["QUEUED", "DISPATCHED"]))):
                TASK.transition(s, task, "CANCELLED", ACTOR, "Agent removal")
                run = s.get(AssessmentRun, task.assessment_run_id) if task.assessment_run_id else None
                if run is not None and run.status in ("QUEUED", "RUNNING"):
                    run.finished_at = utcnow()
                    ASSESSMENT.transition(s, run, "CANCELLED", ACTOR, "Agent removal")
                cancelled += 1
        tracker.ok("STOP_ASSESSMENTS", f"{cancelled} task(s) cancelled; scheduler skips agents being removed")

        winrm = ctx.registry.get(Protocol.WINRM)
        tracker.start("CONNECT", f"WinRM HTTPS {ip}:5986")
        cred = await ctx.vault.resolve("OT-WINDOWS-INSTALLER", purpose=f"removal {removal_id}",
                                       correlation_id=get_correlation_id())
        res, session = await winrm.open_session(Target(ip, port=5986, credential=cred))
        if session is None:
            raise StepFailed("CONNECT", f"WINRM_{res.status.value}", res.error_detail or res.status.value)
        tracker.ok("CONNECT", f"Session created as {cred.username}")
        try:
            await self._steps(removal_id, agent_id, asset_id, tracker, winrm, session)
        finally:
            await winrm.close_session(session)

    async def _steps(self, removal_id: str, agent_id: str, asset_id: str, tracker: StepTracker, winrm,
                     session: RemoteSession) -> None:
        db = self.ctx.db
        tracker.start("STOP_AGENT", "Stop-Service OTProbeAgent")
        r = await winrm.execute(session, RemoteOperation.STOP_SERVICE, {"name": "OTProbeAgent"})
        tracker.ok("STOP_AGENT", "Service stopped" if r.ok else "Service not present (already stopped)")

        tracker.start("UNINSTALL", "msiexec /x ProbeAgent /qn")
        r = await winrm.execute(session, RemoteOperation.UNINSTALL_AGENT, {})
        if not r.ok:
            raise StepFailed("UNINSTALL", r.error_code or "UNINSTALL_FAILED", r.error_detail or "Uninstall failed")
        tracker.ok("UNINSTALL", "Agent uninstalled (exit code 0)")

        tracker.start("REVOKE_IDENTITY", "Revoking the agent credential")
        with db.session() as s:
            agent = s.get(Agent, agent_id)
            revoke_agent(s, agent, ACTOR, "Agent removed")
            prefix = agent.credential_prefix
        tracker.ok("REVOKE_IDENTITY", f"Credential {prefix}… revoked: any further call is rejected (401)")

        tracker.start("REMOVE_TEMP_FILES", f"Remove-Item {STAGING}")
        await winrm.execute(session, RemoteOperation.REMOVE_FILES, {"paths": [STAGING]})
        tracker.ok("REMOVE_TEMP_FILES", "Staging and temporary files removed")

        tracker.start("VALIDATE_DEVICE", "Verifying nothing of the agent remains")
        installed = (await winrm.execute(session, RemoteOperation.QUERY_AGENT_INSTALLED, {})).raw.get("installed")
        query = await winrm.execute(session, RemoteOperation.QUERY_SERVICE, {"name": "OTProbeAgent"})
        service = query.raw.get("service")
        if installed or service:
            raise StepFailed("VALIDATE_DEVICE", "RESIDUE_FOUND", "Agent files or service still present on host")
        tracker.ok("VALIDATE_DEVICE", "No agent files, no OTProbeAgent service")

        tracker.start("ROLLBACK_COMPLETED", "Finalising")
        with db.session() as s:
            rem = s.get(Removal, removal_id)
            agent = s.get(Agent, agent_id)
            agent.removed_at = rem.finished_at = utcnow()
            AGENT.transition(s, agent, "REMOVED", ACTOR)
            REMOVAL.transition(s, rem, "COMPLETED", ACTOR, details={"agentId": agent_id})
            asset = s.get(Asset, asset_id)
            asset.agent_state = "REMOVED"
            events.stage(s, "asset.updated", "asset", asset_id, {"agentState": "REMOVED"})
        tracker.ok("ROLLBACK_COMPLETED", "ROLLBACK COMPLETED: agentInstalled=false, agentStatus=REMOVED. "
                                         "Assessment history, findings, deployments and audit log retained")
