"""Simulated credential vault: real encrypted storage of synthetic secrets in the OTProbe DB."""

from __future__ import annotations

from sqlalchemy import select

from app.adapters.base import Credential, CredentialVault, MaskedCredential
from app.core import audit
from app.core.crypto import MASK
from app.core.db import Database
from app.models import CredentialProfile


class SimulatedCredentialVault(CredentialVault):
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
        return MaskedCredential(row.name, row.protocol, row.username, MASK, bool(row.secret_ciphertext))

    async def describe(self, profile: str) -> MaskedCredential:
        with self.db.session() as s:
            row = s.scalar(select(CredentialProfile).where(CredentialProfile.name == profile))
            if row is None:
                raise KeyError(profile)
            return self._mask(row)

    async def list_profiles(self) -> list[MaskedCredential]:
        with self.db.session() as s:
            return [self._mask(r) for r in s.scalars(select(CredentialProfile).order_by(CredentialProfile.name))]
