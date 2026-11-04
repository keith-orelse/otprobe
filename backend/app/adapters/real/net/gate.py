"""The network gate: the only path from OTProbe to the plant network (docs/SAFETY_AND_SCOPE.md §6).

Every function in ``app.adapters.real.net`` that sends a packet does so inside ``NetworkGate.permit(ip, op)``, which

1. refuses addresses outside the scan scope, or inside an exclusion, and everything when no scope exists (S1-S3);
2. refuses everything while the kill switch is engaged (S6);
3. enforces the safety profile's rate limits: global and per-scope-entry packets per second, per-host concurrency,
   and a minimum gap between operations to one host (S5);
4. counts every decision for the job that is running, for the audit trail (S10).

Scope and safety state are pushed in by the services (``load``) and cached here, so a check costs no DB query.
"""

from __future__ import annotations

import asyncio
import contextvars
import ipaddress
import time
from collections import Counter
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from typing import AsyncIterator, Callable, Iterable, Iterator

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class Profile:
    name: str
    pps: float               # packets (operations) per second to one scope entry
    host_concurrency: int    # parallel operations to one host
    host_gap_sec: float      # minimum time between operations to one host
    retries: int
    plugins: bool            # OT protocol plugins allowed at all


PROFILES = {
    "IT": Profile("IT", pps=50, host_concurrency=2, host_gap_sec=0.2, retries=2, plugins=True),
    "OT_SENSITIVE": Profile("OT_SENSITIVE", pps=10, host_concurrency=1, host_gap_sec=1.0, retries=0, plugins=False),
}


@dataclass(frozen=True)
class ScopeEntry:
    id: str
    network: IPNetwork
    kind: str                         # INCLUDE | EXCLUDE
    profile: str = "OT_SENSITIVE"
    plugins: tuple[str, ...] = ()


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str                       # ok | no-scope | out-of-scope | excluded | kill-switch | invalid-address
    entry: ScopeEntry | None = None
    profile: Profile | None = None


class GateBlocked(Exception):
    def __init__(self, ip: str, reason: str) -> None:
        super().__init__(f"{ip}: {reason}")
        self.ip, self.reason = ip, reason


MESSAGES = {
    "no-scope": "No scan scope configured (scanning disabled)",
    "out-of-scope": "Address is outside the scan scope",
    "excluded": "Address is excluded from the scan scope",
    "kill-switch": "Stopped by the kill switch",
    "invalid-address": "Not a valid IP address",
}


class _Bucket:
    """Token bucket. ``take`` waits until a token is free; tokens refill continuously at ``rate`` per second."""

    def __init__(self, rate: float, clock: Callable[[], float]) -> None:
        self.rate, self.clock = rate, clock
        self.capacity = max(1.0, rate)
        self.tokens, self.updated = self.capacity, clock()
        self.lock = asyncio.Lock()

    async def take(self, sleep) -> None:
        async with self.lock:
            while True:
                now = self.clock()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1 - 1e-9:      # tolerance: float rounding must never leave a sub-ns wait loop
                    self.tokens = max(0.0, self.tokens - 1)
                    return
                await sleep((1 - self.tokens) / self.rate)


@dataclass
class JobStats:
    sent: Counter = field(default_factory=Counter)       # op -> count
    blocked: Counter = field(default_factory=Counter)    # reason -> count
    waited_sec: float = 0.0

    def as_dict(self) -> dict:
        return {"sent": sum(self.sent.values()), "byOperation": dict(self.sent),
                "blocked": dict(self.blocked), "rateLimitedSec": round(self.waited_sec, 2)}


_stats: contextvars.ContextVar[JobStats | None] = contextvars.ContextVar("gate_stats", default=None)


class NetworkGate:
    def __init__(self, max_pps: float = 50.0, clock: Callable[[], float] = time.monotonic, sleep=asyncio.sleep,
                 profiles: dict[str, Profile] | None = None) -> None:
        self.clock, self.sleep = clock, sleep
        self.profiles = profiles or PROFILES
        self.includes: list[ScopeEntry] = []
        self.excludes: list[ScopeEntry] = []
        self.armed = True
        self.safe_mode = True
        self._global = _Bucket(max_pps, clock)
        self._entry_buckets: dict[str, _Bucket] = {}
        self._host_sems: dict[str, asyncio.Semaphore] = {}
        self._host_last: dict[str, float] = {}
        self.totals = JobStats()

    # ---- state pushed in by the scope / safety services ------------------------------------------------------

    def load(self, entries: Iterable[ScopeEntry | dict], armed: bool, safe_mode: bool) -> None:
        """``entries`` may be ScopeEntry objects or plain dicts {id, cidr, kind, profile, plugins} (what the
        services pass, so they never import this module)."""
        entries = [e if isinstance(e, ScopeEntry) else
                   ScopeEntry(e["id"], ipaddress.ip_network(e["cidr"], strict=False), e["kind"],
                              e.get("profile", "OT_SENSITIVE"), tuple(e.get("plugins") or ()))
                   for e in entries]
        self.includes = [e for e in entries if e.kind == "INCLUDE"]
        self.excludes = [e for e in entries if e.kind == "EXCLUDE"]
        self.armed, self.safe_mode = armed, safe_mode
        self._entry_buckets.clear()

    def close(self) -> None:
        """Kill switch: every later ``permit`` is refused, including callers already waiting on a rate limit."""
        self.armed = False

    @property
    def configured(self) -> bool:
        return bool(self.includes)

    # ---- decisions ----------------------------------------------------------------------------------------------

    def profile_of(self, entry: ScopeEntry) -> Profile:
        return self.profiles["OT_SENSITIVE" if self.safe_mode else entry.profile]

    def decide(self, ip: str) -> Decision:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return Decision(False, "invalid-address")
        if not self.armed:
            return Decision(False, "kill-switch")
        if not self.includes:
            return Decision(False, "no-scope")
        if any(addr in e.network for e in self.excludes):
            return Decision(False, "excluded")
        # Most specific INCLUDE wins, so a /28 inside a /24 can carry its own profile.
        matches = [e for e in self.includes if addr in e.network]
        if not matches:
            return Decision(False, "out-of-scope")
        entry = max(matches, key=lambda e: e.network.prefixlen)
        return Decision(True, "ok", entry, self.profile_of(entry))

    def plugin_allowed(self, ip: str, plugin: str) -> bool:
        d = self.decide(ip)
        return d.allowed and d.profile.plugins and plugin in d.entry.plugins

    # ---- the permit ------------------------------------------------------------------------------------------------

    def count_blocked(self, reason: str) -> None:
        for stats in (_stats.get(), self.totals):
            if stats is not None:
                stats.blocked[reason] += 1

    @asynccontextmanager
    async def permit(self, ip: str, op: str) -> AsyncIterator[Decision]:
        d = self.decide(ip)
        if not d.allowed:
            self.count_blocked(d.reason)
            raise GateBlocked(ip, d.reason)
        profile = d.profile
        sem = self._host_sems.setdefault(ip, asyncio.Semaphore(profile.host_concurrency))
        started = self.clock()
        async with sem:
            gap = self._host_last.get(ip, -1e9) + profile.host_gap_sec - self.clock()
            if gap > 0:
                await self.sleep(gap)
            bucket = self._entry_buckets.setdefault(d.entry.id, _Bucket(profile.pps, self.clock))
            await bucket.take(self.sleep)
            await self._global.take(self.sleep)
            again = self.decide(ip)          # the kill switch or the scope may have changed while we waited
            if not again.allowed:
                self.count_blocked(again.reason)
                raise GateBlocked(ip, again.reason)
            self._host_last[ip] = self.clock()
            waited = self.clock() - started
            for stats in (_stats.get(), self.totals):
                if stats is not None:
                    stats.sent[op] += 1
                    stats.waited_sec += waited
            yield again

    @contextmanager
    def track(self) -> Iterator[JobStats]:
        """Collect counters for everything sent inside this block (including tasks it spawns)."""
        stats = JobStats()
        token = _stats.set(stats)
        try:
            yield stats
        finally:
            _stats.reset(token)
