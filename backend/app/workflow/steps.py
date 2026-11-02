"""Persisted, live-updating workflow steps (drive the step lists in the UI)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from app.core import events
from app.core.clock import utcnow
from app.core.db import Database
from app.models import WorkflowStep


class StepTracker:
    def __init__(self, db: Database, kind: str, workflow_id: str, topic: str) -> None:
        self.db, self.kind, self.workflow_id, self.topic = db, kind, workflow_id, topic

    def plan(self, names: list[str]) -> None:
        with self.db.session() as s:
            for seq, name in enumerate(names, start=1):
                s.add(WorkflowStep(workflow_kind=self.kind, workflow_id=self.workflow_id, seq=seq, name=name))

    def _update(self, name: str, **fields: Any) -> None:
        with self.db.session() as s:
            step = s.scalar(select(WorkflowStep).where(WorkflowStep.workflow_id == self.workflow_id,
                                                       WorkflowStep.name == name))
            if step is None:
                seq = (s.scalar(select(WorkflowStep.seq).where(WorkflowStep.workflow_id == self.workflow_id)
                                .order_by(WorkflowStep.seq.desc()).limit(1)) or 0) + 1
                step = WorkflowStep(workflow_kind=self.kind, workflow_id=self.workflow_id, seq=seq, name=name)
                s.add(step)
            for k, v in fields.items():
                if k == "data":
                    if v is None:
                        continue
                    v = {**(step.data or {}), **v}
                setattr(step, k, v)
            s.flush()
            events.stage(s, f"{self.topic}.step", self.topic, self.workflow_id,
                         {"name": step.name, "seq": step.seq, "status": step.status, "detail": step.detail,
                          "progress": step.progress, "data": step.data})

    def start(self, name: str, detail: str = "") -> None:
        self._update(name, status="RUNNING", detail=detail, started_at=utcnow())

    def update(self, name: str, detail: str | None = None, progress: float | None = None,
               data: dict[str, Any] | None = None) -> None:
        fields: dict[str, Any] = {}
        if detail is not None:
            fields["detail"] = detail
        if progress is not None:
            fields["progress"] = progress
        if data is not None:
            fields["data"] = data
        self._update(name, **fields)

    def ok(self, name: str, detail: str = "", data: dict[str, Any] | None = None) -> None:
        self._update(name, status="OK", detail=detail, data=data, finished_at=utcnow())

    def fail(self, name: str, detail: str, data: dict[str, Any] | None = None) -> None:
        self._update(name, status="FAILED", detail=detail, data=data, finished_at=utcnow())

    def skip(self, name: str, detail: str) -> None:
        self._update(name, status="SKIPPED", detail=detail, finished_at=utcnow())

    def skip_remaining(self, detail: str) -> None:
        with self.db.session() as s:
            for step in s.scalars(select(WorkflowStep).where(WorkflowStep.workflow_id == self.workflow_id,
                                                             WorkflowStep.status.in_(["PENDING", "RUNNING"]))):
                step.status, step.detail, step.finished_at = "SKIPPED", detail, utcnow()
                events.stage(s, f"{self.topic}.step", self.topic, self.workflow_id,
                             {"name": step.name, "seq": step.seq, "status": step.status, "detail": detail})
