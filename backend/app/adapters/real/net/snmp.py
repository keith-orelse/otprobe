"""SNMP GET / walk through pysnmp. Read-only by construction: this module never builds a SetRequest.

Credential profiles: ``params.version`` = "3" (default) or "2c". For v3, ``params.auth`` / ``params.priv`` name the
protocols, the profile secret is the auth passphrase and ``params.privSecret`` (optional) the privacy passphrase.
For v2c the secret is the community string."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
    usmAesCfb128Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoPrivProtocol,
    walk_cmd,
)

from app.adapters.base import Credential
from app.adapters.real.net.gate import NetworkGate

AUTH = {"SHA": usmHMACSHAAuthProtocol, "SHA-256": usmHMAC192SHA256AuthProtocol,
        "SHA-512": usmHMAC384SHA512AuthProtocol, "MD5": usmHMACMD5AuthProtocol}
PRIV = {"AES-128": usmAesCfb128Protocol, "AES-256": usmAesCfb256Protocol, "DES": usmDESPrivProtocol,
        "NONE": usmNoPrivProtocol}


@dataclass
class SnmpReply:
    status: str                                   # OK | TIMEOUT | AUTH_FAILED | ERROR
    values: dict[str, Any] = field(default_factory=dict)   # dotted OID -> python value
    error: str | None = None


def auth_data(cred: Credential):
    params = cred.params or {}
    if str(params.get("version", "3")) == "2c":
        return CommunityData(cred.secret, mpModel=1)
    priv = params.get("priv", "AES-128")
    return UsmUserData(cred.username, authKey=cred.secret,
                       privKey=None if priv == "NONE" else params.get("privSecret", cred.secret),
                       authProtocol=AUTH[params.get("auth", "SHA-256")], privProtocol=PRIV[priv])


def _value(v: Any) -> Any:
    if v.__class__.__name__ in ("NoSuchObject", "NoSuchInstance", "EndOfMibView"):
        return None
    if v.__class__.__name__ == "OctetString":
        raw = bytes(v)
        try:
            text = raw.decode()
            return text if text.isprintable() or not text else raw.hex(":").upper()
        except UnicodeDecodeError:
            return raw.hex(":").upper()
    if v.__class__.__name__ == "ObjectIdentifier":
        return str(v)
    try:
        return int(v)
    except (TypeError, ValueError):
        return str(v)


def _classify(error_indication: Any) -> tuple[str, str]:
    text = str(error_indication)
    low = text.lower()
    if "timed out" in low or "timeout" in low or "no snmp response" in low:
        return "TIMEOUT", text
    if any(k in low for k in ("digest", "unknown user", "unknownusername", "authentication", "decryption")):
        return "AUTH_FAILED", text
    return "ERROR", text


async def get(gate: NetworkGate, ip: str, cred: Credential, oids: list[str], timeout_sec: float,
              port: int = 161) -> SnmpReply:
    async with gate.permit(ip, "SNMP_GET"):
        engine = SnmpEngine()
        try:
            target = await UdpTransportTarget.create((ip, port), timeout=timeout_sec, retries=0)
            err, status, index, binds = await get_cmd(engine, auth_data(cred), target, ContextData(),
                                                      *[ObjectType(ObjectIdentity(o)) for o in oids])
        finally:
            engine.close_dispatcher()
    if err:
        kind, text = _classify(err)
        return SnmpReply(kind, error=text)
    if status:
        return SnmpReply("ERROR", error=f"{status.prettyPrint()} at index {index}")
    return SnmpReply("OK", {str(name): _value(val) for name, val in binds})


async def walk(gate: NetworkGate, ip: str, cred: Credential, oid: str, timeout_sec: float, max_rows: int = 256,
               port: int = 161) -> SnmpReply:
    """GETNEXT walk of one subtree, as one gate operation, capped at ``max_rows``."""
    rows: dict[str, Any] = {}
    async with gate.permit(ip, "SNMP_WALK"):
        engine = SnmpEngine()
        try:
            target = await UdpTransportTarget.create((ip, port), timeout=timeout_sec, retries=0)
            async for err, status, index, binds in walk_cmd(engine, auth_data(cred), target, ContextData(),
                                                            ObjectType(ObjectIdentity(oid)), lexicographicMode=False):
                if err:
                    kind, text = _classify(err)
                    return SnmpReply(kind, rows, text)
                if status:
                    return SnmpReply("ERROR", rows, f"{status.prettyPrint()} at index {index}")
                for name, val in binds:
                    rows[str(name)] = _value(val)
                if len(rows) >= max_rows:
                    break
        finally:
            engine.close_dispatcher()
    return SnmpReply("OK", rows)
