"""Agent release registry (docs/GO_AGENT.md §1). A release folder (<dist>/<version>/) is accepted only when
SHA256SUMS.sig verifies against the configured Ed25519 release key AND every binary's SHA-256 matches SHA256SUMS.
There is no way to register an unsigned build: without AGENT_RELEASE_PUBKEY nothing is accepted."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import schemas
from app.context import AppContext
from app.core import audit
from app.core.audit import Actor
from app.models import AgentBuild, Package

log = logging.getLogger("otprobe.agent_builds")

# Which OS products each build serves (prefix match on os.product, as for the deployment precheck).
SUPPORTED_OS = {
    ("windows", "modern"): ["Windows 10", "Windows 11", "Windows Server 2016", "Windows Server 2019",
                            "Windows Server 2022", "Windows Server 2025"],
    ("windows", "legacy"): ["Windows 7", "Windows 8.1", "Windows Server 2008 R2", "Windows Server 2012"],
    ("linux", "modern"): ["Ubuntu", "Debian", "Red Hat", "Rocky", "AlmaLinux", "CentOS", "Oracle Linux", "SUSE", "SLES",
                          "openSUSE", "Fedora", "Alpine", "Raspbian"],
    ("linux", "legacy"): ["CentOS", "Red Hat", "Oracle Linux"],
    ("darwin", "modern"): ["macOS"],
}


def package_id(version: str, build_id: str) -> str:
    return f"agent-{version}-{build_id}"


def _sync_package(session: Session, b: AgentBuild) -> None:
    """Each verified build is deployable as a package, so the existing request/approve/precheck/deploy flow uses it."""
    pid = package_id(b.version, b.build_id)
    pkg = session.get(Package, pid)
    if pkg is None:
        pkg = Package(id=pid)
        session.add(pkg)
    pkg.name, pkg.version, pkg.architecture = f"OTProbe Agent ({b.build_id})", b.version, f"{b.os}/{b.arch}"
    pkg.sha256, pkg.size_bytes, pkg.status = b.sha256, b.size_bytes, "ACTIVE"
    pkg.supported_os = SUPPORTED_OS.get((b.os, b.variant), [])
    pkg.release_notes = f"Signed release {b.version}, {b.variant} build for {b.min_os or b.os}"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_release(folder: Path, pubkey_b64: str) -> tuple[list[dict], str | None]:
    """Returns (builds, None) for a valid release, or ([], reason) when it must be rejected."""
    if not pubkey_b64:
        return [], "no release public key configured (AGENT_RELEASE_PUBKEY): unsigned releases are never accepted"
    sums_file, sig_file, manifest_file = folder / "SHA256SUMS", folder / "SHA256SUMS.sig", folder / "manifest.json"
    for f in (sums_file, sig_file, manifest_file):
        if not f.exists():
            return [], f"{f.name} missing"
    sums = sums_file.read_bytes()
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey_b64)).verify(
            base64.b64decode(sig_file.read_text().strip()), sums)
    except (InvalidSignature, ValueError):
        return [], "signature does not verify against the release key"
    listed = {}
    for line in sums.decode().splitlines():
        parts = line.split()
        if len(parts) == 2:
            listed[parts[1].lstrip("*")] = parts[0].lower()
    manifest = json.loads(manifest_file.read_text())
    builds = []
    for b in manifest.get("builds", []):
        name = b["file"]
        if Path(name).name != name or name not in listed:
            return [], f"{name} is not covered by the signed SHA256SUMS"
        actual = _sha256(folder / name) if (folder / name).exists() else None
        if actual != listed[name]:
            return [], f"{name}: SHA-256 does not match the signed SHA256SUMS (file changed or missing)"
        builds.append({**b, "path": str(folder / name), "sha256": actual})
    return builds, None


def rescan(ctx: AppContext, session: Session, actor: Actor) -> schemas.AgentBuildScan:
    root = Path(ctx.settings.agent_dist_dir)
    registered, rejected = [], []
    for folder in sorted(p for p in root.glob("*") if p.is_dir()) if root.is_dir() else []:
        version = folder.name
        builds, reason = verify_release(folder, ctx.settings.agent_release_pubkey)
        if reason:
            rejected.append({"version": version, "reason": reason})
            audit.record(session, actor, "AGENT_RELEASE_REJECTED", "agent_release", version, {"reason": reason})
            for stale in session.scalars(select(AgentBuild).where(AgentBuild.version == version)):
                pkg = session.get(Package, package_id(stale.version, stale.build_id))
                if pkg is not None:
                    pkg.status = "BLOCKED"          # existing deployments keep their history; nothing new deploys
                session.delete(stale)     # a release that no longer verifies is withdrawn
            continue
        new = 0
        for b in builds:
            bid = f"{version}/{b['id']}"
            row = session.get(AgentBuild, bid)
            if row is None:
                row = AgentBuild(id=bid, version=version, build_id=b["id"], os=b["os"], arch=b["arch"],
                                 variant=b["variant"], file=b["file"], path=b["path"], sha256=b["sha256"],
                                 size_bytes=b["size"], min_os=b.get("minOs", ""))
                session.add(row)
                new += 1
            elif row.sha256 != b["sha256"]:
                row.sha256, row.path, row.size_bytes = b["sha256"], b["path"], b["size"]
            _sync_package(session, row)
        if new:
            audit.record(session, actor, "AGENT_RELEASE_REGISTERED", "agent_release", version,
                         {"builds": len(builds), "new": new})
        registered.append({"version": version, "builds": len(builds)})
    session.flush()
    for r in rejected:
        log.warning("agent release %s rejected: %s", r["version"], r["reason"])
    return schemas.AgentBuildScan(registered=registered, rejected=rejected)


def list_builds(session: Session) -> list[schemas.AgentBuild]:
    rows = session.scalars(select(AgentBuild).order_by(AgentBuild.version.desc(), AgentBuild.build_id))
    return [schemas.AgentBuild.model_validate(r) for r in rows]
