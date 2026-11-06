"""Environment-driven settings. See docs/ARCHITECTURE.md §10."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _repo_path(rel: str, fallback: str) -> str:
    local = Path(__file__).resolve().parents[3] / rel
    return str(local) if local.exists() else fallback


def _default_rules_dir() -> str:
    local = Path(__file__).resolve().parents[3] / "rules"
    return str(local) if local.is_dir() else "/app/rules"


def _read(path: str | None) -> str:
    return Path(path).read_text().strip() if path and Path(path).exists() else ""


@dataclass(frozen=True)
class Settings:
    speed_factor: float = 1.0
    seed: int = 42
    heartbeat_interval_sec: float = 10.0
    assessment_interval_sec: float = 300.0
    enrollment_token_ttl_sec: int = 900
    enrollment_timeout_sec: float = 120.0
    adapter_mode: str = "real"          # "real" = live network; "simulated" only with tests/sim (DECISIONS L6-1)
    adapter_overrides: str = ""
    database_url: str = "sqlite:///./otprobe.db"
    rules_dir: str = field(default_factory=_default_rules_dir)
    jwt_secret: str = "change-me-demo-jwt-secret-at-least-32-bytes"
    sim_service_token: str = "change-me-sim-token"
    vault_key: str = ""
    agent_server_url: str = "http://127.0.0.1:8000"
    precheck_valid_sec: float = 1800.0
    assessment_timeout_sec: float = 120.0
    telemetry_time_scale: float = 1.0   # scales telemetry staleness windows (tests use < 1)
    telemetry_retention: int = 10_000
    run_migrations: bool = True
    # Live network (docs/SAFETY_AND_SCOPE.md)
    safe_mode: bool = True              # initial value; admins change it at runtime (safety_state)
    scan_max_pps: float = 50.0          # global ceiling for active discovery, packets per second
    vault_key_file: str = ""            # file holding the vault key; generated next to the DB if absent
    admin_password: str = ""            # first-start passwords for the seeded accounts (generated if empty)
    operator_password: str = ""
    approver_password: str = ""
    agent_dist_dir: str = field(default_factory=lambda: _repo_path("agent-go/dist", "/data/agent-dist"))
    agent_release_pubkey: str = ""      # base64 Ed25519 public key (or AGENT_RELEASE_PUBKEY_FILE)
    public_url: str = ""                # what agents and install scripts use, e.g. https://192.168.0.160:8000
    tls_ca_file: str = ""               # CA that signed the server certificate; its SHA-256 is pinned in agents

    @property
    def live(self) -> bool:
        return self.adapter_mode == "real"

    @property
    def ca_sha256(self) -> str:
        """SHA-256 of the CA certificate (DER) that agents pin; empty when no CA file is configured."""
        if not self.tls_ca_file or not Path(self.tls_ca_file).exists():
            return ""
        import hashlib

        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        cert = x509.load_pem_x509_certificate(Path(self.tls_ca_file).read_bytes())
        return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()

    @classmethod
    def from_env(cls, **overrides) -> "Settings":
        env = os.environ
        values = dict(
            speed_factor=float(env.get("SPEED_FACTOR", 1.0)),
            seed=int(env.get("SEED", 42)),
            heartbeat_interval_sec=float(env.get("HEARTBEAT_INTERVAL_SEC", 10)),
            assessment_interval_sec=float(env.get("ASSESSMENT_INTERVAL_SEC", 300)),
            assessment_timeout_sec=float(env.get("ASSESSMENT_TIMEOUT_SEC", 120)),
            telemetry_time_scale=float(env.get("TELEMETRY_TIME_SCALE", 1.0)),
            enrollment_token_ttl_sec=int(env.get("ENROLLMENT_TOKEN_TTL_SEC", 900)),
            enrollment_timeout_sec=float(env.get("ENROLLMENT_TIMEOUT_SEC", 120)),
            adapter_mode=env.get("ADAPTER_MODE", "real"),
            adapter_overrides=env.get("ADAPTER_OVERRIDES", ""),
            database_url=env.get("DATABASE_URL", "sqlite:///./otprobe.db"),
            rules_dir=env.get("RULES_DIR", _default_rules_dir()),
            jwt_secret=env.get("JWT_SECRET", "change-me-demo-jwt-secret-at-least-32-bytes"),
            sim_service_token=env.get("SIM_SERVICE_TOKEN", "change-me-sim-token"),
            vault_key=env.get("VAULT_KEY", ""),
            agent_server_url=env.get("AGENT_SERVER_URL", "http://127.0.0.1:8000"),
            safe_mode=env.get("SAFE_MODE", "true").lower() not in ("0", "false", "no"),
            scan_max_pps=float(env.get("SCAN_MAX_PPS", 50)),
            vault_key_file=env.get("VAULT_KEY_FILE", ""),
            admin_password=env.get("OTPROBE_ADMIN_PASSWORD", ""),
            operator_password=env.get("OTPROBE_OPERATOR_PASSWORD", ""),
            approver_password=env.get("OTPROBE_APPROVER_PASSWORD", ""),
            agent_dist_dir=env.get("AGENT_DIST_DIR", _repo_path("agent-go/dist", "/data/agent-dist")),
            agent_release_pubkey=env.get("AGENT_RELEASE_PUBKEY", "") or _read(env.get("AGENT_RELEASE_PUBKEY_FILE")),
            public_url=env.get("OTPROBE_PUBLIC_URL", ""),
            tls_ca_file=env.get("OTPROBE_TLS_CA_FILE", ""),
        )
        values.update(overrides)
        return cls(**values)
