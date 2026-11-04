"""Audit event names for protocol failures, as listed in docs/FAILURE_MATRIX.md."""

from app.adapters.base import ResultStatus

WINRM_EVENTS = {
    ResultStatus.REFUSED: "WINRM_CONNECTION_REFUSED",
    ResultStatus.TIMEOUT: "WINRM_TIMEOUT",
    ResultStatus.DISABLED: "WINRM_DISABLED",
    ResultStatus.AUTH_FAILED: "WINRM_AUTH_FAILED",
    ResultStatus.TLS_INVALID: "WINRM_TLS_INVALID",
    ResultStatus.UNREACHABLE: "ASSET_UNREACHABLE",
}
SNMP_EVENTS = {ResultStatus.TIMEOUT: "SNMP_TIMEOUT", ResultStatus.AUTH_FAILED: "SNMP_AUTH_FAILED"}


def winrm_event(status: ResultStatus) -> str:
    return WINRM_EVENTS.get(status, f"WINRM_{status.value}")
