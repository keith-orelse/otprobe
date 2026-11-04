"""Config-driven adapter selection. Engines only ever see the interfaces from app.adapters.base."""

from __future__ import annotations

from typing import Any

from app.adapters.base import REQUIRED_PROTOCOLS, Protocol, ProtocolAdapter


def parse_overrides(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in (raw or "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out


class AdapterRegistry:
    def __init__(self, mode: str = "real", overrides: dict[str, str] | None = None) -> None:
        self.mode = mode
        self.overrides = overrides or {}
        self._impls: dict[tuple[Protocol, str], ProtocolAdapter] = {}

    def register(self, protocol: Protocol, implementation: str, adapter: ProtocolAdapter) -> None:
        self._impls[(protocol, implementation)] = adapter

    def selected(self, protocol: Protocol) -> str:
        return self.overrides.get(protocol.value.lower(), self.mode)

    def get(self, protocol: Protocol) -> Any:
        impl = self.selected(protocol)
        try:
            return self._impls[(protocol, impl)]
        except KeyError:
            raise RuntimeError(f"No {impl} adapter registered for protocol '{protocol.value.lower()}'") from None

    def has(self, protocol: Protocol) -> bool:
        return (protocol, self.selected(protocol)) in self._impls

    def validate(self) -> None:
        for p in REQUIRED_PROTOCOLS:
            self.get(p)

    def implementations(self, protocol: Protocol) -> dict[str, ProtocolAdapter]:
        return {impl: a for (p, impl), a in self._impls.items() if p == protocol}

    def describe(self) -> list[dict[str, Any]]:
        out = []
        for p in Protocol:
            if not self.has(p):
                continue
            d = self.get(p).descriptor()
            out.append({"protocol": p.value, "implementation": d.implementation, "simulated": d.simulated,
                        "label": d.display_label})
        return out
