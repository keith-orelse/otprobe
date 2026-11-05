//go:build windows

package collectors

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// Fixed, read-only PowerShell scripts (Windows PowerShell 3.0+). Same shapes as the agentless WinRM scripts.
const psJSON = " | ConvertTo-Json -Compress -Depth 4"

var psScripts = map[string]string{
	"os": "$o = Get-CimInstance Win32_OperatingSystem; $v = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'; " +
		"[pscustomobject]@{caption=$o.Caption; build=$o.BuildNumber; ubr=$v.UBR; displayVersion=$v.DisplayVersion; " +
		"releaseId=$v.ReleaseId; productType=$o.ProductType}" + psJSON,
	"firewall": "Get-NetFirewallProfile | ForEach-Object { @{name=$_.Name; enabled=[bool]$_.Enabled; " +
		"inbound=[string]$_.DefaultInboundAction} }" + psJSON,
	"antivirus": "$m = $null; try { $m = Get-CimInstance -Namespace root/Microsoft/Windows/Defender MSFT_MpComputerStatus " +
		"-ErrorAction Stop } catch {}; $s = @(); try { $s = @(Get-CimInstance -Namespace root/SecurityCenter2 " +
		"AntiVirusProduct -ErrorAction Stop | ForEach-Object { @{name=$_.displayName; state=$_.productState} }) } catch {}; " +
		"[pscustomobject]@{defender=$(if ($m) { @{service=[bool]$m.AMServiceEnabled; realtime=[bool]$m.RealTimeProtectionEnabled; " +
		"signatureAge=$m.AntivirusSignatureAge} } else { $null }); securityCenter=$s}" + psJSON,
	"hotfixes": "@(Get-HotFix | ForEach-Object { @{id=$_.HotFixID; installedOn=$(if ($_.InstalledOn) " +
		"{ $_.InstalledOn.ToString('yyyy-MM-dd') } else { $null })} })" + psJSON,
	"software": "$k = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', " +
		"'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', " +
		"'Registry::HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; " +
		"@(Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.SystemComponent -ne 1 } | " +
		"ForEach-Object { @{name=$_.DisplayName; version=$_.DisplayVersion; publisher=$_.Publisher} })" + psJSON,
	"services": "@(Get-Service | Where-Object Status -eq 'Running' | ForEach-Object { @{name=$_.Name; " +
		"startType=[string]$_.StartType} })" + psJSON,
	"admins": "@(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $u = $null; if ($_.PrincipalSource -eq 'Local' " +
		"-and $_.ObjectClass -eq 'User') { $u = Get-LocalUser -SID $_.SID -ErrorAction SilentlyContinue }; " +
		"@{name=$_.Name; class=[string]$_.ObjectClass; source=[string]$_.PrincipalSource; " +
		"enabled=$(if ($u) { [bool]$u.Enabled } else { $true })} })" + psJSON,
	"smb": "try { @{v1=[bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol}" + psJSON + " } catch { '{}' }",
	"listening": "@(Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort -Unique)" + psJSON,
}

func ps(ctx context.Context, name string) (json.RawMessage, error) {
	out, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", psScripts[name])
	if err != nil {
		return nil, err
	}
	return json.RawMessage(strings.TrimSpace(out)), nil
}

func platform() []Collector {
	return []Collector{
		{"os", "os", winOS},
		{"firewall", "firewall", winFirewall},
		{"antivirus", "antivirus", winAntivirus},
		{"patches", "patches", winPatches},
		{"software", "software", winSoftware},
		{"services", "services", winServices},
		{"local_admins", "local_admins", winAdmins},
		{"password_policy", "password_policy", winPasswordPolicy},
		{"audit", "audit", winAudit},
		{"usb", "usb", winUSB},
		{"rdp", "rdp", winRDP},
		{"smb", "smb", winSMB},
	}
}

func winOS(ctx context.Context) (interface{}, error) {
	raw, err := ps(ctx, "os")
	if err != nil {
		return nil, err
	}
	return MapWindowsOS(raw)
}

func winFirewall(ctx context.Context) (interface{}, error) {
	raw, err := ps(ctx, "firewall")
	if err != nil {
		return nil, err
	}
	return MapWindowsFirewall(raw)
}

func winAntivirus(ctx context.Context) (interface{}, error) {
	raw, err := ps(ctx, "antivirus")
	if err != nil {
		return nil, err
	}
	return MapWindowsAntivirus(raw)
}

func winPatches(ctx context.Context) (interface{}, error) {
	raw, err := ps(ctx, "hotfixes")
	if err != nil {
		return nil, err
	}
	return MapWindowsHotfixes(raw, time.Now()), nil
}

func winSoftware(ctx context.Context) (interface{}, error) {
	raw, err := ps(ctx, "software")
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"installed": MapWindowsSoftware(raw)}, nil
}

func winServices(ctx context.Context) (interface{}, error) {
	raw, err := ps(ctx, "services")
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"running": AsList(raw)}, nil
}

func winAdmins(ctx context.Context) (interface{}, error) {
	raw, err := ps(ctx, "admins")
	if err != nil {
		return nil, err
	}
	return MapWindowsAdmins(raw), nil
}

func winPasswordPolicy(ctx context.Context) (interface{}, error) {
	out, err := run(ctx, "net", "accounts")
	if err != nil {
		return nil, err
	}
	section := ParseNetAccounts(out)
	tmp := filepath.Join(os.TempDir(), "otprobe-secpol.inf")
	defer os.Remove(tmp)
	if _, err := run(ctx, "secedit", "/export", "/areas", "SECURITYPOLICY", "/cfg", tmp); err == nil {
		if data, err := os.ReadFile(tmp); err == nil {
			if complex, ok := ParseSeceditComplexity(decodeUTF16(data)); ok {
				section["complexity"] = complex
			}
		}
	}
	return section, nil
}

func winAudit(ctx context.Context) (interface{}, error) {
	out, err := run(ctx, "auditpol", "/get", "/subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}", "/r")
	if err != nil {
		return nil, err
	}
	if v := ParseAuditpolLogon(out); v != "" {
		return map[string]interface{}{"logon_events": v}, nil
	}
	return nil, errors.New("auditpol output not understood")
}

func regDword(path, name string) (uint64, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	return v, err == nil
}

func winUSB(ctx context.Context) (interface{}, error) {
	policy := "allowed"
	if v, ok := regDword(`SYSTEM\CurrentControlSet\Services\USBSTOR`, "Start"); ok && v == 4 {
		policy = "blocked"
	} else if v, ok := regDword(`SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}`, "Deny_Write"); ok && v == 1 {
		policy = "read_only"
	}
	return map[string]interface{}{"storage_policy": policy}, nil
}

func winRDP(ctx context.Context) (interface{}, error) {
	deny, _ := regDword(`SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections")
	nla, _ := regDword(`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "UserAuthentication")
	return map[string]interface{}{"enabled": deny == 0, "nla_required": nla == 1}, nil
}

func winSMB(ctx context.Context) (interface{}, error) {
	raw, err := ps(ctx, "smb")
	if err != nil {
		return nil, err
	}
	var v map[string]interface{}
	if json.Unmarshal(raw, &v) != nil || v["v1"] == nil {
		return nil, errors.New("SMB server configuration not available")
	}
	return map[string]interface{}{"v1_enabled": v["v1"]}, nil
}

func listeningPorts(ctx context.Context) ([]int, error) {
	raw, err := ps(ctx, "listening")
	if err != nil {
		return nil, err
	}
	var ports []int
	if json.Unmarshal(raw, &ports) != nil {
		var one int
		if json.Unmarshal(raw, &one) == nil {
			ports = []int{one}
		}
	}
	return ports, nil
}

func Fingerprint() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	guid := ""
	if err == nil {
		guid, _, _ = k.GetStringValue("MachineGuid")
		k.Close()
	}
	return hashParts(guid, Hostname())
}
