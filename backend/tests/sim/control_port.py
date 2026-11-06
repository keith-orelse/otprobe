"""Port for the test Demo Controls (moved out of app.adapters.base in L6)."""

from __future__ import annotations

import abc
from typing import Any, Mapping


class SimulationControl(abc.ABC):
    """Port for admin Demo Controls. Only a simulated implementation exists; a real deployment would not register
    one, and the demo endpoints would return 404."""

    @abc.abstractmethod
    def devices(self) -> list[dict[str, Any]]: ...

    @abc.abstractmethod
    def set_fault(self, device_id: str, fault: str, params: Mapping[str, Any], set_by: str) -> None: ...

    @abc.abstractmethod
    def clear_fault(self, device_id: str, fault: str) -> None: ...

    @abc.abstractmethod
    def inject_rogue(self) -> dict[str, Any]: ...

    @abc.abstractmethod
    def reset(self) -> None:
        """Rebuild the simulated world from seed (Reset POC)."""

    @abc.abstractmethod
    def apply_config(self, device_id: str, control: str, value: str) -> str:
        """Change host configuration; returns a human-readable description of the effect."""
