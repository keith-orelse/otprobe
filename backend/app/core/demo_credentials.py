"""Synthetic demo credentials, shared by the simulated devices (which accept them) and the simulated vault
(which stores them encrypted). None of these values is valid anywhere outside the POC."""

WINDOWS_READONLY = ("OT-WINDOWS-READONLY", "WinRM", "demo\\otprobe-ro", "Ro-Demo-Pass-2026!")
WINDOWS_INSTALLER = ("OT-WINDOWS-INSTALLER", "WinRM", "demo\\agent-installer", "Inst-Demo-Pass-2026!")
SNMPV3_RO = ("OT-SNMPV3-RO", "SNMP", "otprobe-snmp", "Snmp-Auth-Demo-2026")
LINUX_SSH_RO = ("OT-LINUX-SSH-RO", "SSH", "otprobe-ro", "Ssh-Demo-Pass-2026!")

ALL = (WINDOWS_READONLY, WINDOWS_INSTALLER, SNMPV3_RO, LINUX_SSH_RO)
