"""Demo-grade secret encryption for the simulated credential vault."""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet

MASK = "••••••••"


def fernet_for(vault_key: str) -> Fernet:
    # An empty VAULT_KEY derives a fixed demo key. Acceptable only because every secret is synthetic.
    key = vault_key or base64.urlsafe_b64encode(hashlib.sha256(b"otprobe-demo-vault-key").digest()).decode()
    return Fernet(key.encode())


def sha256_hex(value: str | bytes) -> str:
    data = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()
