"""Local credential vault: secrets encrypted at rest (Fernet / AES-128-CBC + HMAC) in the OTProbe DB.

Used in both modes. In live mode the key comes from VAULT_KEY / VAULT_KEY_FILE (see app.core.crypto); secrets are
never returned by the API, only masked descriptions."""

from __future__ import annotations

from typing import Any, Mapping

from sqlalchemy import select

from app.adapters.base import Credential, CredentialVault, MaskedCredential
from app.core import audit
from app.core.crypto import MASK
from app.core.db import Database
from app.models import CredentialProfile


class LocalCredentialVault(CredentialVault):
    def __init__(self, db: Database, fernet) -> None:
        self.db, self.fernet = db, fernet

    async def resolve(self, profile: str, *, purpose: str, correlation_id: str) -> Credential:
        with self.db.session() as s:
            row = s.scalar(select(CredentialProfile).where(CredentialProfile.name == profile))
            if row is None:
                raise KeyError(f"credential profile {profile} not found")
            audit.record(s, audit.system("credential-vault"), "CREDENTIAL_RETRIEVED", "credential_profile", row.name,
                         {"profile": row.name, "purpose": purpose, "username": row.username})
            secret = self.fernet.decrypt(row.secret_ciphertext.encode()).decode()
            return Credential(row.name, row.username, secret, dict(row.params))

    @staticmethod
    def _mask(row: CredentialProfile) -> MaskedCredential:
        port = (row.params or {}).get("port")
        return MaskedCredential(row.name, row.protocol, row.username, MASK, bool(row.secret_ciphertext),
                                int(port) if port else None)

    async def describe(self, profile: str) -> MaskedCredential:
        with self.db.session() as s:
            row = s.scalar(select(CredentialProfile).where(CredentialProfile.name == profile))
            if row is None:
                raise KeyError(profile)
            return self._mask(row)

    async def list_profiles(self) -> list[MaskedCredential]:
        with self.db.session() as s:
            return [self._mask(r) for r in s.scalars(select(CredentialProfile).order_by(CredentialProfile.name))]

    async def store(self, profile: str, protocol: str, username: str, secret: str | None,
                    params: Mapping[str, Any], description: str) -> MaskedCredential:
        with self.db.session() as s:
            row = s.scalar(select(CredentialProfile).where(CredentialProfile.name == profile))
            if row is None:
                if not secret:
                    raise ValueError("a new credential profile needs a secret")
                row = CredentialProfile(name=profile, protocol=protocol, username=username, params=dict(params),
                                        description=description, secret_ciphertext="")
                s.add(row)
            row.protocol, row.username, row.params, row.description = protocol, username, dict(params), description
            if secret:
                row.secret_ciphertext = self.fernet.encrypt(secret.encode()).decode()
            s.flush()
            return self._mask(row)

    async def delete(self, profile: str) -> None:
        with self.db.session() as s:
            row = s.scalar(select(CredentialProfile).where(CredentialProfile.name == profile))
            if row is None:
                raise KeyError(profile)
            s.delete(row)
