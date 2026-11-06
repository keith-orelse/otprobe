"""Values placed into agent install commands, on Windows (PowerShell) and Linux (sh). Every value is validated
against these patterns before it is put in a script; the patterns leave no room for quotes or shell syntax."""

from __future__ import annotations

import re

AGENT_PARAMS = {
    "sha256": re.compile(r"^[0-9a-f]{64}$"),
    "token": re.compile(r"^enr_[A-Za-z0-9_-]{20,128}$"),
    "server_url": re.compile(r"^https://[A-Za-z0-9.-]{1,253}(:\d{1,5})?/?$"),
    "ca_sha256": re.compile(r"^([0-9a-f]{64})?$"),
    "deployment_id": re.compile(r"^[0-9a-f-]{36}$"),
    "profile": re.compile(r"^[a-z0-9-]{1,48}$"),
}
