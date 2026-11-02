import itertools

import pytest
from sqlalchemy import select

from app.core.audit import system
from app.core.db import Database
from app.core.errors import ProblemError
from app.core.migrations import upgrade
from app.models import AuditEvent, DiscoveryJob
from app.workflow.machine import DISCOVERY, MACHINES, PROBE

EXPECTED = {
    "discovery": {("QUEUED", "RUNNING"), ("QUEUED", "CANCELLED"), ("RUNNING", "COMPLETED"), ("RUNNING", "FAILED"),
                  ("RUNNING", "CANCELLED")},
    "probe": {("QUEUED", "RUNNING"), ("QUEUED", "FAILED"), ("RUNNING", "COMPLETED"), ("RUNNING", "PARTIAL"),
              ("RUNNING", "FAILED")},
}


@pytest.mark.parametrize("kind", sorted(EXPECTED))
def test_exactly_declared_edges_are_allowed(kind):
    m = MACHINES[kind]
    allowed = {(a, b) for a, b in itertools.product(m.states, repeat=2) if m.allowed(a, b)}
    assert allowed == EXPECTED[kind]


def test_terminal_states_have_no_exit():
    for m, terminal in ((DISCOVERY, {"COMPLETED", "FAILED", "CANCELLED"}), (PROBE, {"COMPLETED", "PARTIAL", "FAILED"})):
        assert not any(m.allowed(t, to) for t in terminal for to in m.states)


def test_transition_audits_and_rejects_invalid(tmp_path):
    url = f"sqlite:///{tmp_path / 'sm.db'}"
    upgrade(url)
    db = Database(url)
    actor = system("test")
    with db.session() as s:
        job = DiscoveryJob(targets=["192.168.20.0/24"], methods=["ARP"], requested_by="t", correlation_id="c1")
        DISCOVERY.create(s, job, actor)
        DISCOVERY.transition(s, job, "RUNNING", actor)
        with pytest.raises(ProblemError) as err:
            DISCOVERY.transition(s, job, "QUEUED", actor)
        assert err.value.status == 409 and "cannot go from RUNNING to QUEUED" in err.value.detail
        actions = [e.action for e in s.scalars(select(AuditEvent).order_by(AuditEvent.seq))]
    assert actions == ["DISCOVERY_REQUESTED", "DISCOVERY_STARTED"]
    db.dispose()
