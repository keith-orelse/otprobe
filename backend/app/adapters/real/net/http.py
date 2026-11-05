"""One GET / for the page title and Server header (web HMIs, switch and gateway UIs). No login, no crawling, no
other paths. Certificates are not verified: only a title is read, and nothing is sent but the GET."""

from __future__ import annotations

import html
import re

import httpx

from app.adapters.real.net.gate import NetworkGate

_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
MAX_BODY = 64 * 1024


async def title(gate: NetworkGate, ip: str, port: int, tls: bool, timeout_sec: float) -> dict:
    url = f"{'https' if tls else 'http'}://{ip}:{port}/"
    async with gate.permit(ip, "HTTP_GET_ROOT"):
        async with httpx.AsyncClient(verify=False, timeout=timeout_sec, follow_redirects=False) as client:
            async with client.stream("GET", url, headers={"User-Agent": "OTProbe (read-only inventory)"}) as r:
                body = b""
                async for chunk in r.aiter_bytes():
                    body += chunk
                    if len(body) >= MAX_BODY:
                        break
    m = _TITLE.search(body)
    return {"status": r.status_code, "server": r.headers.get("server"),
            "title": html.unescape(m.group(1).decode(errors="replace")).strip()[:200] if m else None}
