"""On startup, fail any workflow left mid-flight by a restart (history kept, nothing half-resumed)."""

from __future__ import annotations

from sqlalchemy import select

from app.core import audit
from app.core.audit import system
from app.core.clock import utcnow
from app.core.db import Database
from app.models import DiscoveryJob, ProbeRun, WorkflowStep
from app.workflow.machine import DISCOVERY, PROBE

REASON = "Interrupted by server restart"


def recover_interrupted(db: Database) -> int:
    actor = system("startup-recovery")
    count = 0
    with db.session() as s:
        for model, machine, targets in (
            (DiscoveryJob, DISCOVERY, {"QUEUED": "CANCELLED", "RUNNING": "FAILED"}),
            (ProbeRun, PROBE, {"QUEUED": "FAILED", "RUNNING": "FAILED"}),
        ):
            for row in s.scalars(select(model).where(model.status.in_(list(targets)))):
                ident = row.id
                machine.transition(s, row, targets[row.status], actor, REASON)
                row.error = REASON
                row.finished_at = utcnow()
                audit.record(s, actor, "WORKFLOW_INTERRUPTED", machine.entity_kind, ident, {"reason": REASON})
                for step in s.scalars(select(WorkflowStep).where(WorkflowStep.workflow_id == ident,
                                                                 WorkflowStep.status.in_(["PENDING", "RUNNING"]))):
                    step.status = "FAILED" if step.status == "RUNNING" else "SKIPPED"
                    step.detail, step.finished_at = REASON, utcnow()
                count += 1
    return count
