"""Network gate guarantees S1-S6 (docs/SAFETY_AND_SCOPE.md §1), with a fake clock so rate limits are exact."""

from __future__ import annotations

import asyncio

import pytest

from app.adapters.real.net.gate import GateBlocked, NetworkGate


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, sec: float) -> None:
        self.sleeps.append(sec)
        self.now += sec
        await asyncio.sleep(0)


def gate(entries, *, armed=True, safe_mode=False, max_pps=1000.0, clock=None) -> NetworkGate:
    clock = clock or FakeClock()
    g = NetworkGate(max_pps=max_pps, clock=clock, sleep=clock.sleep)
    g.load(entries, armed=armed, safe_mode=safe_mode)
    return g


def inc(cidr, profile="IT", plugins=(), id_=None):
    return {"id": id_ or cidr, "cidr": cidr, "kind": "INCLUDE", "profile": profile, "plugins": list(plugins)}


def exc(cidr):
    return {"id": f"x-{cidr}", "cidr": cidr, "kind": "EXCLUDE"}


@pytest.mark.parametrize("entries, ip, reason", [
    ([], "10.0.0.5", "no-scope"),                                   # S2: nothing configured, nothing sent
    ([inc("10.0.0.0/24")], "10.0.1.5", "out-of-scope"),            # S1
    ([inc("10.0.0.0/24"), exc("10.0.0.5/32")], "10.0.0.5", "excluded"),   # S3: exclusion wins
    ([inc("10.0.0.0/24")], "not-an-ip", "invalid-address"),
])
async def test_refused_addresses_raise_before_anything_is_sent(entries, ip, reason):
    g = gate(entries)
    with pytest.raises(GateBlocked) as err:
        async with g.permit(ip, "ICMP_ECHO"):
            pytest.fail("the body must not run")
    assert err.value.reason == reason
    assert g.totals.blocked[reason] == 1 and not g.totals.sent


async def test_in_scope_address_is_allowed_and_counted():
    g = gate([inc("10.0.0.0/24")])
    with g.track() as stats:
        async with g.permit("10.0.0.5", "TCP_CONNECT") as d:
            assert d.allowed and d.profile.name == "IT"
    assert stats.sent["TCP_CONNECT"] == 1 and stats.as_dict()["sent"] == 1


def test_most_specific_entry_decides_the_profile():
    g = gate([inc("10.0.0.0/24", "IT"), inc("10.0.0.0/28", "OT_SENSITIVE")])
    assert g.decide("10.0.0.3").profile.name == "OT_SENSITIVE"
    assert g.decide("10.0.0.200").profile.name == "IT"


def test_safe_mode_forces_ot_sensitive_and_disables_plugins():
    g = gate([inc("10.0.0.0/24", "IT", plugins=["modbus"])], safe_mode=True)
    assert g.decide("10.0.0.5").profile.name == "OT_SENSITIVE"
    assert not g.plugin_allowed("10.0.0.5", "modbus")
    g.load([inc("10.0.0.0/24", "IT", plugins=["modbus"])], armed=True, safe_mode=False)
    assert g.plugin_allowed("10.0.0.5", "modbus") and not g.plugin_allowed("10.0.0.5", "s7")


async def test_kill_switch_refuses_new_and_waiting_operations():
    clock = FakeClock()
    g = gate([inc("10.0.0.0/24", "OT_SENSITIVE")], clock=clock)
    async with g.permit("10.0.0.5", "ICMP_ECHO"):
        pass

    async def second():
        async with g.permit("10.0.0.5", "ICMP_ECHO"):
            pytest.fail("must not run after the kill switch")

    original_sleep = clock.sleep

    async def sleep_then_stop(sec):     # the kill switch fires while the caller waits for its rate-limit slot
        g.close()
        await original_sleep(sec)

    g.sleep = sleep_then_stop
    with pytest.raises(GateBlocked, match="kill-switch"):
        await second()
    with pytest.raises(GateBlocked, match="kill-switch"):
        async with g.permit("10.0.0.6", "ICMP_ECHO"):
            pass
    assert g.totals.sent["ICMP_ECHO"] == 1


async def test_ot_sensitive_spaces_operations_to_one_host_by_one_second():
    clock = FakeClock()
    g = gate([inc("10.0.0.0/24", "OT_SENSITIVE")], clock=clock)
    times = []
    for _ in range(3):
        async with g.permit("10.0.0.5", "TCP_CONNECT"):
            times.append(clock.now)
    assert [round(b - a, 3) for a, b in zip(times, times[1:], strict=False)] == [1.0, 1.0]


async def test_entry_rate_limit_caps_packets_per_second_across_hosts():
    clock = FakeClock()
    g = gate([inc("10.0.0.0/24", "OT_SENSITIVE")], clock=clock)     # 10 pps for the entry
    for i in range(30):
        async with g.permit(f"10.0.0.{i + 1}", "ICMP_ECHO"):
            pass
    # 10 tokens are available at once, then 1 every 0.1 s: 20 more packets need 2 s.
    assert clock.now == pytest.approx(2.0, abs=0.01)


async def test_global_ceiling_applies_on_top_of_profiles():
    clock = FakeClock()
    g = gate([inc("10.0.0.0/24", "IT")], max_pps=5.0, clock=clock)
    for i in range(10):
        async with g.permit(f"10.0.0.{i + 1}", "ICMP_ECHO"):
            pass
    assert clock.now == pytest.approx(1.0, abs=0.01)


async def test_narrowing_the_scope_applies_to_the_next_packet():
    g = gate([inc("10.0.0.0/24")])
    async with g.permit("10.0.0.5", "ICMP_ECHO"):
        pass
    g.load([inc("10.0.0.0/28")], armed=True, safe_mode=False)
    with pytest.raises(GateBlocked, match="out-of-scope"):
        async with g.permit("10.0.0.50", "ICMP_ECHO"):
            pass
