"""SIMULATION CONTROLS (admin only). Phase 3 exposes device faults; the full Demo Controls set arrives in Phase 5."""

from __future__ import annotations

from app import schemas
from app.context import AppContext
from app.core import audit
from app.core.errors import ProblemError
from app.core.principal import CurrentUser

FAULTS = {
    "heartbeat_blocked": "Break agent heartbeat (network path drops agent traffic)",
    "agent_crashed": "Crash the agent process (restart via service)",
    "device_offline": "Power off / disconnect the device",
    "winrm_disabled": "WinRM service disabled",
    "winrm_refused": "WinRM connection refused",
    "winrm_timeout": "WinRM connection timeout",
    "winrm_bad_credentials": "WinRM rejects the credential",
    "winrm_bad_certificate": "WinRM presents an untrusted certificate",
    "icmp_blocked": "ICMP filtered",
    "snmp_timeout": "SNMP does not answer",
    "package_checksum_mismatch": "Package corrupted in transit (hash mismatch)",
    "install_failure": "Agent installer fails (exit 1603)",
    "enrollment_failure": "Agent presents an invalid enrollment token",
    "server_unreachable": "Host cannot reach the OTProbe server (:443)",
}


def _control(ctx: AppContext):
    if ctx.sim_control is None:
        raise ProblemError(404, "not-found", "Simulation controls are not available")
    return ctx.sim_control


def state(ctx: AppContext) -> schemas.DemoState:
    return schemas.DemoState(devices=[schemas.DemoDevice.model_validate(d) for d in _control(ctx).devices()],
                             available_faults=FAULTS)


def apply_fault(ctx: AppContext, device_id: str, req: schemas.DemoFault, user: CurrentUser):
    if req.fault not in FAULTS:
        raise ProblemError(422, "unknown-fault", "Unknown simulation control",
                           f"Available: {', '.join(sorted(FAULTS))}")
    control = _control(ctx)
    try:
        if req.enabled:
            control.set_fault(device_id, req.fault, req.params, user.username)
        else:
            control.clear_fault(device_id, req.fault)
    except KeyError:
        raise ProblemError(404, "not-found", "Simulated device not found", device_id) from None

    def action(session):
        audit.record(session, user.actor, "DEMO_CONTROL_APPLIED", "sim_device", device_id,
                     {"control": req.fault, "enabled": req.enabled, "params": req.params})
        dev = next(d for d in control.devices() if d["deviceId"] == device_id)
        return schemas.DemoDevice.model_validate(dev).dump(), None

    return action
