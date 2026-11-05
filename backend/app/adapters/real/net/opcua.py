"""OPC UA: GetEndpoints only. No session is created, so no Read, Write or Call is possible."""

from __future__ import annotations

from asyncua import Client

from app.adapters.real.net.gate import NetworkGate


async def endpoints(gate: NetworkGate, ip: str, timeout_sec: float, port: int = 4840) -> dict:
    async with gate.permit(ip, "OPCUA_GET_ENDPOINTS"):
        client = Client(f"opc.tcp://{ip}:{port}", timeout=timeout_sec)
        eps = await client.connect_and_get_server_endpoints()
    if not eps:
        return {}
    server = eps[0].Server
    return {"application_name": server.ApplicationName.Text, "application_uri": server.ApplicationUri,
            "product_uri": server.ProductUri,
            "security_policies": sorted({e.SecurityPolicyUri.rsplit("#", 1)[-1] for e in eps}),
            "security_modes": sorted({e.SecurityMode.name for e in eps})}
