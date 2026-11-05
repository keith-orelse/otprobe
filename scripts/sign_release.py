"""Sign an agent release (Ed25519) so the OTProbe server only accepts binaries you built.

    python scripts/sign_release.py --generate-key keys/otprobe-release
        -> keys/otprobe-release.key (PRIVATE: keep it off the OTProbe server, back it up offline)
           keys/otprobe-release.pub (public: give it to the server as AGENT_RELEASE_PUBKEY_FILE)
    python scripts/sign_release.py agent-go/dist/1.2.0 --key keys/otprobe-release.key
        -> agent-go/dist/1.2.0/SHA256SUMS.sig

The signature covers SHA256SUMS; the server checks the signature, then every file's hash against SHA256SUMS.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate(prefix: Path) -> None:
    key = Ed25519PrivateKey.generate()
    prefix.parent.mkdir(parents=True, exist_ok=True)
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    fd = os.open(f"{prefix}.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(fd, "wb") as f:
        f.write(priv)
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    Path(f"{prefix}.pub").write_text(base64.b64encode(raw).decode() + "\n")
    print(f"wrote {prefix}.key (private, 0400) and {prefix}.pub (public)")


def sign(release: Path, key_file: Path) -> None:
    sums = (release / "SHA256SUMS").read_bytes()
    key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
    (release / "SHA256SUMS.sig").write_text(base64.b64encode(key.sign(sums)).decode() + "\n")
    print(f"signed {release / 'SHA256SUMS'} ({len(sums.splitlines())} files)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("release", nargs="?", type=Path)
    ap.add_argument("--key", type=Path)
    ap.add_argument("--generate-key", type=Path, metavar="PREFIX")
    a = ap.parse_args()
    if a.generate_key:
        generate(a.generate_key)
    elif a.release and a.key:
        sign(a.release, a.key)
    else:
        ap.print_help()
        sys.exit(2)
