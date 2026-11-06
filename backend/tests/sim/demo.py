"""SIMULATION CONTROLS (admin only): device faults, host configuration and rogue devices for the test simulator."""

from __future__ import annotations

from app.context import AppContext
from app.core import audit
from app.core.errors import ProblemError
from app.core.principal import CurrentUser
from tests.sim import schemas

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
    "assessment_timeout": "Agent accepts assessment tasks but never uploads evidence",
    "rollback_failure": "Agent uninstall fails (exit 1603) during removal",
    "plc_offline": "PLC stops responding and stops publishing status",
    "sensor_value_override": "Force a sensor reading (params: {\"value\": 97.0})",
}

CONFIG_VALUES = {
    "firewall": ("enabled", "disabled"),
    "antivirus": ("running", "stopped"),
    "unauthorized_software": ("install", "remove"),
    "remove_patch": ("latest",),
}


def _control(ctx: AppContext):
    return ctx.extras["sim_control"]


def state(ctx: AppContext) -> schemas.DemoState:
    return schemas.DemoState(devices=[schemas.DemoDevice.model_validate(d) for d in _control(ctx).devices()],
                             available_faults=FAULTS,
                             config_controls={k: list(v) for k, v in CONFIG_VALUES.items()})


def apply_fault(ctx: AppContext, device_id: str, req: schemas.DemoFault, user: CurrentUser):
    if req.fault == "sensor_value_override" and req.enabled and not isinstance(req.params.get("value"), (int, float)):
        raise ProblemError(422, "invalid-params", "sensor_value_override needs a numeric params.value")
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


def apply_config(ctx: AppContext, device_id: str, req: schemas.DemoConfig, user: CurrentUser):
    if req.value not in CONFIG_VALUES[req.control]:
        raise ProblemError(422, "invalid-value", "Invalid value for control",
                           f"{req.control} accepts {', '.join(CONFIG_VALUES[req.control])}")
    control = _control(ctx)
    try:
        detail = control.apply_config(device_id, req.control, req.value)
    except KeyError:
        raise ProblemError(404, "not-found", "Simulated device not found", device_id) from None
    except ValueError as exc:
        raise ProblemError(409, "not-applicable", "Control not applicable to this device", str(exc)) from None

    def action(session):
        audit.record(session, user.actor, "DEMO_CONTROL_APPLIED", "sim_device", device_id,
                     {"control": req.control, "value": req.value, "effect": detail})
        dev = next(d for d in control.devices() if d["deviceId"] == device_id)
        return schemas.DemoDevice.model_validate(dev).dump(), None

    return action


def inject_rogue(ctx: AppContext, user: CurrentUser):
    control = _control(ctx)
    dev = control.inject_rogue()

    def action(session):
        audit.record(session, user.actor, "DEMO_CONTROL_APPLIED", "sim_device", dev["deviceId"],
                     {"control": "inject_rogue", **dev,
                      "message": "Rogue device added to the simulated network; run discovery to detect it"})
        return dev, None

    return action
