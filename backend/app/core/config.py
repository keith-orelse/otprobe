"""Environment-driven settings. See docs/ARCHITECTURE.md §10."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _default_rules_dir() -> str:
    local = Path(__file__).resolve().parents[3] / "rules"
    return str(local) if local.is_dir() else "/app/rules"


@dataclass(frozen=True)
class Settings:
    speed_factor: float = 1.0
    seed: int = 42
    heartbeat_interval_sec: int = 10
    assessment_interval_sec: int = 300
    enrollment_token_ttl_sec: int = 900
    enrollment_timeout_sec: int = 120
    adapter_mode: str = "simulated"
    adapter_overrides: str = ""
    database_url: str = "sqlite:///./otprobe.db"
    rules_dir: str = field(default_factory=_default_rules_dir)
    jwt_secret: str = "change-me-jwt-secret"
    sim_service_token: str = "change-me-sim-token"
    vault_key: str = ""
    run_migrations: bool = True

    @classmethod
    def from_env(cls, **overrides) -> "Settings":
        env = os.environ
        values = dict(
            speed_factor=float(env.get("SPEED_FACTOR", 1.0)),
            seed=int(env.get("SEED", 42)),
            heartbeat_interval_sec=int(env.get("HEARTBEAT_INTERVAL_SEC", 10)),
            assessment_interval_sec=int(env.get("ASSESSMENT_INTERVAL_SEC", 300)),
            enrollment_token_ttl_sec=int(env.get("ENROLLMENT_TOKEN_TTL_SEC", 900)),
            enrollment_timeout_sec=int(env.get("ENROLLMENT_TIMEOUT_SEC", 120)),
            adapter_mode=env.get("ADAPTER_MODE", "simulated"),
            adapter_overrides=env.get("ADAPTER_OVERRIDES", ""),
            database_url=env.get("DATABASE_URL", "sqlite:///./otprobe.db"),
            rules_dir=env.get("RULES_DIR", _default_rules_dir()),
            jwt_secret=env.get("JWT_SECRET", "change-me-jwt-secret"),
            sim_service_token=env.get("SIM_SERVICE_TOKEN", "change-me-sim-token"),
            vault_key=env.get("VAULT_KEY", ""),
        )
        values.update(overrides)
        return cls(**values)
