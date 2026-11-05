"""Create a lab CA and a server certificate so agents can reach OTProbe over HTTPS with the CA pinned.

    backend/.venv/bin/python scripts/make_lab_tls.py 192.168.0.160 [more IPs or hostnames]

Writes backend/tls/ (git-ignored):
    otprobe-ca.pem        the CA certificate: OTPROBE_TLS_CA_FILE (its SHA-256 is pinned in every agent)
    otprobe-ca.key        the CA private key (keep it; needed to issue a new server certificate)
    otprobe-server.pem    server certificate + CA (full chain: the agent checks the pinned CA is in it)
    otprobe-server.key    server private key
Then start the API with:  --ssl-certfile tls/otprobe-server.pem --ssl-keyfile tls/otprobe-server.key
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import os
import socket
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = Path(__file__).resolve().parents[1] / "backend" / "tls"


def write_key(path: Path, key) -> None:
    data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def main(names: list[str], out: Path = OUT) -> str:
    """Writes the four files into ``out`` and returns the CA SHA-256 that agents pin."""
    out.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OTProbe Lab CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
          .not_valid_after(now + dt.timedelta(days=825))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                       crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    sans: list[x509.GeneralName] = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                                    x509.DNSName(socket.gethostname())]
    for n in names:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            sans.append(x509.DNSName(n))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0] if names else "otprobe")]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=397))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    (out / "otprobe-ca.pem").write_bytes(ca.public_bytes(pem))
    write_key(out / "otprobe-ca.key", ca_key)
    (out / "otprobe-server.pem").write_bytes(cert.public_bytes(pem) + ca.public_bytes(pem))
    write_key(out / "otprobe-server.key", key)
    pin = hashlib.sha256(ca.public_bytes(serialization.Encoding.DER)).hexdigest()
    print(f"wrote {out}/  (server names: {', '.join(str(s.value) for s in sans)})")
    print(f"CA SHA-256 pinned in agents: {pin}")
    return pin


if __name__ == "__main__":
    main(sys.argv[1:])
