"""MQTT topic rules shared by the broker adapter and the account service: wildcard matching, device usernames and topic
prefixes, and Mosquitto's password hash format."""

from __future__ import annotations

import base64
import hashlib
import os
import re
from typing import Any, Sequence


def topic_matches(topic_filter: str, topic: str) -> bool:
    """MQTT topic filter matching with + (one level) and # (remaining levels)."""
    f_parts, t_parts = topic_filter.split("/"), topic.split("/")
    for i, f in enumerate(f_parts):
        if f == "#":
            return True
        if i >= len(t_parts) or (f != "+" and f != t_parts[i]):
            return False
    return len(f_parts) == len(t_parts)


READER = "otprobe-reader"               # OTProbe's own subscriber: read-only, never publishes
RESERVED_PREFIX = "otprobe"             # device usernames may not start with this
ITERATIONS = 1000
SALT_BYTES = 12

USERNAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,63}$")
TOPIC_LEVEL = r"[A-Za-z0-9_.-]+"
TOPIC_PREFIX = re.compile(rf"^{TOPIC_LEVEL}(/{TOPIC_LEVEL}){{0,9}}$")


def password_hash(password: str, salt: bytes | None = None, iterations: int = ITERATIONS) -> str:
    """Mosquitto's PBKDF2-SHA512 format, as written by ``mosquitto_passwd``: $7$<iterations>$<salt>$<hash>."""
    salt = salt if salt is not None else os.urandom(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha512", password.encode(), salt, iterations, 64)
    return f"$7${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def check_password(password: str, hashed: str) -> bool:
    try:
        _, kind, iterations, salt, digest = hashed.split("$")
    except ValueError:
        return False
    if kind != "7":
        return False
    expected = base64.b64decode(digest)
    return hashlib.pbkdf2_hmac("sha512", password.encode(), base64.b64decode(salt), int(iterations),
                               len(expected)) == expected


def valid_username(name: str) -> bool:
    return bool(USERNAME.match(name)) and not name.startswith(RESERVED_PREFIX)


def valid_prefix(prefix: str) -> bool:
    """Plain topic levels only: no wildcards, no $ (system topics), no leading or trailing slash, at most 10 levels."""
    return len(prefix) <= 200 and bool(TOPIC_PREFIX.match(prefix))


def overlaps(a: str, b: str) -> bool:
    """Two accounts may never share topics, so every message has exactly one possible publisher."""
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def owner(topic: str, accounts: Sequence[Any]) -> str | None:
    """The account allowed to publish ``topic`` (the broker refuses everyone else)."""
    for a in accounts:
        if topic == a.topic_prefix or topic.startswith(a.topic_prefix + "/"):
            return a.username
    return None
