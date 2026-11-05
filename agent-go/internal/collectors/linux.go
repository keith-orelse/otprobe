//go:build linux

package collectors

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func platform() []Collector {
	return []Collector{
		{"os", "os", linuxOS},
		{"firewall", "firewall", linuxFirewall},
		{"packages", "software", linuxPackages},
		{"software", "software", linuxPackages},
		{"patches", "patches", linuxPatches},
		{"services", "services", linuxServices},
		{"admins", "admins", linuxAdmins},
		{"local_admins", "admins", linuxAdmins},
		{"password_policy", "password_policy", linuxPasswordPolicy},
		{"ssh", "ssh", linuxSSH},
		{"audit", "audit", linuxAudit},
		{"usb", "usb", linuxUSB},
	}
}

func readFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

func linuxOS(ctx context.Context) (interface{}, error) {
	rel := ParseOSRelease(readFile("/etc/os-release"))
	kernel := strings.TrimSpace(readFile("/proc/sys/kernel/osrelease"))
	return map[string]interface{}{"family": "linux", "name": rel["PRETTY_NAME"], "product": rel["NAME"],
		"id": rel["ID"], "version_id": rel["VERSION_ID"], "version": rel["VERSION_ID"], "kernel": kernel}, nil
}

func linuxFirewall(ctx context.Context) (interface{}, error) {
	if out, err := run(ctx, "nft", "list", "ruleset"); err == nil && strings.TrimSpace(out) != "" {
		state := "disabled"
		if strings.Contains(out, "hook input") && (strings.Contains(out, "policy drop") || strings.Count(out, "\n") > 6) {
			state = "enabled"
		}
		return map[string]interface{}{"state": state, "backend": "nftables"}, nil
	}
	if out, err := run(ctx, "iptables-save"); err == nil && strings.TrimSpace(out) != "" {
		state := "disabled"
		if strings.Contains(out, ":INPUT DROP") || strings.Contains(out, "-A INPUT") {
			state = "enabled"
		}
		return map[string]interface{}{"state": state, "backend": "iptables"}, nil
	}
	if cfg := readFile("/etc/ufw/ufw.conf"); cfg != "" {
		state := "disabled"
		if strings.Contains(cfg, "ENABLED=yes") {
			state = "enabled"
		}
		return map[string]interface{}{"state": state, "backend": "ufw"}, nil
	}
	return map[string]interface{}{"state": "disabled", "backend": "none"}, nil
}

func linuxPackages(ctx context.Context) (interface{}, error) {
	for _, cmd := range [][]string{
		{"dpkg-query", "-W", "-f=${Package}\t${Version}\n"},
		{"rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"},
		{"apk", "info", "-v"},
	} {
		if out, err := run(ctx, cmd[0], cmd[1:]...); err == nil && out != "" {
			return map[string]interface{}{"installed": ParsePackages(out)}, nil
		}
	}
	return nil, errNoPackageManager
}

func linuxPatches(ctx context.Context) (interface{}, error) {
	section := map[string]interface{}{}
	if out, err := run(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"); err == nil {
		section["pending_security"] = CountSecurityUpgrades(out) // from the local package cache only
	}
	for _, log := range []string{"/var/log/dpkg.log", "/var/log/dnf.rpm.log", "/var/log/yum.log", "/var/log/apk.log"} {
		if st, err := os.Stat(log); err == nil {
			section["last_update_days"] = int(time.Since(st.ModTime()).Hours() / 24)
			break
		}
	}
	return section, nil
}

func linuxServices(ctx context.Context) (interface{}, error) {
	out, err := run(ctx, "systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain")
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"running": ParseSystemdRunning(out)}, nil
}

func linuxAdmins(ctx context.Context) (interface{}, error) {
	out, _ := run(ctx, "getent", "group", "sudo", "wheel", "admin")
	uid0 := ParseUID0(readFile("/etc/passwd"))
	members := ParseGroupMembers(out)
	return map[string]interface{}{"members": members, "uid0": uid0, "enabled_count": len(members)}, nil
}

func linuxPasswordPolicy(ctx context.Context) (interface{}, error) {
	defs := ParseKeyValues(readFile("/etc/login.defs"), "")
	pwq := ParseKeyValues(readFile("/etc/security/pwquality.conf"), "=")
	fl := ParseKeyValues(readFile("/etc/security/faillock.conf"), "=")
	section := map[string]interface{}{}
	if v, ok := atoi(pwq["minlen"]); ok {
		section["min_length"] = v
	} else if v, ok := atoi(defs["PASS_MIN_LEN"]); ok {
		section["min_length"] = v
	}
	if v, ok := atoi(defs["PASS_MAX_DAYS"]); ok {
		section["max_age_days"] = v
	}
	if v, ok := atoi(fl["deny"]); ok {
		section["lockout_threshold"] = v
	}
	return section, nil
}

func linuxSSH(ctx context.Context) (interface{}, error) {
	out, err := run(ctx, "sshd", "-T")
	if err != nil {
		return nil, err
	}
	c := ParseSSHDConfig(out)
	return map[string]interface{}{"permitrootlogin": c["permitrootlogin"],
		"passwordauthentication": c["passwordauthentication"]}, nil
}

func linuxAudit(ctx context.Context) (interface{}, error) {
	out, _ := run(ctx, "systemctl", "is-active", "auditd")
	state := "stopped"
	if strings.TrimSpace(out) == "active" {
		state = "running"
	}
	return map[string]interface{}{"auditd": state}, nil
}

func linuxUSB(ctx context.Context) (interface{}, error) {
	var conf strings.Builder
	for _, dir := range []string{"/etc/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.conf"))
		for _, f := range files {
			conf.WriteString(readFile(f))
			conf.WriteString("\n")
		}
	}
	return map[string]interface{}{"storage_policy": USBStoragePolicy(conf.String())}, nil
}

func listeningPorts(ctx context.Context) ([]int, error) {
	text := readFile("/proc/net/tcp") + "\n" + strings.Join(strings.Split(readFile("/proc/net/tcp6"), "\n")[1:], "\n")
	return ParseProcNetTCP(text), nil
}

func Fingerprint() string {
	return hashParts(strings.TrimSpace(readFile("/etc/machine-id")),
		strings.TrimSpace(readFile("/sys/class/dmi/id/product_uuid")))
}
