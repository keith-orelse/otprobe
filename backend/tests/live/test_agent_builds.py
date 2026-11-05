"""Agent release registry: only releases signed with the configured key, with every file matching the signed
SHA256SUMS, are accepted (docs/GO_AGENT.md §1)."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.main import create_app
from tests.live.conftest import LiveHarness, live_settings

pytestmark = pytest.mark.live


def make_release(root: Path, version: str, key: Ed25519PrivateKey | None, files: dict[str, bytes]) -> Path:
    folder = root / version
    folder.mkdir(parents=True)
    builds, lines = [], []
    for bid, data in files.items():
        name = f"otprobe-agent-{version}-{bid}{'.exe' if bid.startswith('windows') else ''}"
        (folder / name).write_bytes(data)
        sha = hashlib.sha256(data).hexdigest()
        lines.append(f"{sha}  {name}")
        os_, arch = bid.split("-")[0], bid.split("-")[-1]
        builds.append({"id": bid, "file": name, "os": os_, "arch": arch,
                       "variant": "legacy" if "legacy" in bid else "modern", "sha256": sha, "size": len(data),
                       "minOs": "test"})
    sums = ("\n".join(lines) + "\n").encode()
    (folder / "SHA256SUMS").write_bytes(sums)
    (folder / "manifest.json").write_text(json.dumps({"version": version, "builds": builds}))
    if key is not None:
        (folder / "SHA256SUMS.sig").write_text(base64.b64encode(key.sign(sums)).decode())
    return folder


def pub(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


async def test_only_signed_untampered_releases_are_accepted(tmp_path):
    key, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    dist = tmp_path / "dist"
    make_release(dist, "1.0.0", key, {"windows-amd64": b"MZ agent", "linux-arm64": b"\x7fELF agent"})
    bad = make_release(dist, "1.0.1", key, {"windows-amd64": b"MZ agent 2"})
    (bad / "otprobe-agent-1.0.1-windows-amd64.exe").write_bytes(b"MZ agent 2 + implant")      # tampered after signing
    make_release(dist, "1.0.2", None, {"linux-amd64": b"\x7fELF unsigned"})                   # no signature
    make_release(dist, "1.0.3", other, {"linux-amd64": b"\x7fELF other key"})                 # signed by someone else

    app = create_app(live_settings(tmp_path / "b.db", agent_dist_dir=str(dist), agent_release_pubkey=pub(key)))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            h = await LiveHarness(app, c).login("operator")
            builds = await h.get("/agent-builds")
            assert sorted(b["id"] for b in builds) == ["1.0.0/linux-arm64", "1.0.0/windows-amd64"]
            assert builds[0]["sha256"] == hashlib.sha256(b"\x7fELF agent").hexdigest()

            await h.post("/agent-builds/rescan", expect=403)                       # admin only
            await h.login("admin")
            scan = (await h.post("/agent-builds/rescan", expect=200)).json()
            reasons = {r["version"]: r["reason"] for r in scan["rejected"]}
            assert "does not match the signed SHA256SUMS" in reasons["1.0.1"]
            assert "SHA256SUMS.sig missing" in reasons["1.0.2"]
            assert "signature does not verify" in reasons["1.0.3"]
            assert (await h.get("/audit-events", params={"action": "AGENT_RELEASE_REJECTED"}))["total"] >= 3

            # A registered release that is altered later is withdrawn on the next scan.
            (dist / "1.0.0" / "otprobe-agent-1.0.0-linux-arm64").write_bytes(b"\x7fELF swapped")
            await h.post("/agent-builds/rescan", expect=200)
            assert await h.get("/agent-builds") == []


async def test_nothing_is_accepted_without_a_release_key(tmp_path):
    make_release(tmp_path / "dist", "1.0.0", Ed25519PrivateKey.generate(), {"linux-amd64": b"\x7fELF"})
    app = create_app(live_settings(tmp_path / "b.db", agent_dist_dir=str(tmp_path / "dist")))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            h = await LiveHarness(app, c).login("operator")
            assert await h.get("/agent-builds") == []
