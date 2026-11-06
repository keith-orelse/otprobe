"""Secret encryption for the credential vault, and small hashing helpers."""

from __future__ import annotations

import base64
import hashlib
import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet

MASK = "••••••••"


def fernet_for(vault_key: str) -> Fernet:
    # An empty VAULT_KEY derives a fixed demo key. Only the test simulator uses this (every secret is synthetic);
    # live mode always goes through live_vault_key().
    key = vault_key or base64.urlsafe_b64encode(hashlib.sha256(b"otprobe-demo-vault-key").digest()).decode()
    return Fernet(key.encode())


def live_vault_key(vault_key: str, key_file: str, database_url: str, name: str = "vault") -> str:
    """The given key, else the key file, else a new key written to the key file (0400). Never the demo key.
    ``name`` picks the default file (otprobe-<name>.key next to the DB) when no key file is configured."""
    if vault_key:
        return vault_key
    path = Path(key_file) if key_file else _beside_db(database_url, name)
    if path.exists():
        return path.read_text().strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key().decode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(fd, "w") as f:
        f.write(key)
    logging.getLogger("otprobe").warning("generated a new %s key at %s - back it up", name, path)
    return key


def _beside_db(database_url: str, name: str) -> Path:
    if database_url.startswith("sqlite:///"):
        return Path(database_url.removeprefix("sqlite:///")).resolve().parent / f"otprobe-{name}.key"
    return Path(f"otprobe-{name}.key").resolve()


def sha256_hex(value: str | bytes) -> str:
    data = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()
