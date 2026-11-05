package collectors

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestLinuxParsers(t *testing.T) {
	rel := ParseOSRelease("PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nID=debian\n")
	if rel["PRETTY_NAME"] != "Debian GNU/Linux 12 (bookworm)" || rel["ID"] != "debian" {
		t.Fatalf("os-release: %v", rel)
	}
	pk := ParsePackages("openssh-server\t1:9.2p1-2+deb12u3\nmusl-1.2.5-r0\n")
	if pk[0]["version"] != "1:9.2p1-2+deb12u3" || pk[1]["name"] != "musl" || pk[1]["version"] != "1.2.5-r0" {
		t.Fatalf("packages: %v", pk)
	}
	sv := ParseSystemdRunning("cron.service loaded active running Regular background\nssh.service loaded active running OpenBSD\n")
	if len(sv) != 2 || sv[1]["name"] != "ssh" {
		t.Fatalf("services: %v", sv)
	}
	tcp := "  sl  local_address rem_address   st\n   0: 00000000:0016 00000000:0000 0A 0\n   1: 0100007F:1F90 00000000:0000 01 0\n"
	if got := ParseProcNetTCP(tcp); !reflect.DeepEqual(got, []int{22}) {
		t.Fatalf("proc/net/tcp: %v", got)
	}
	if got := ParseGroupMembers("sudo:x:27:alice,bob\nwheel:x:10:\n"); !reflect.DeepEqual(got, []string{"alice", "bob"}) {
		t.Fatalf("groups: %v", got)
	}
	if got := ParseUID0("root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/:/bin/sh\nbob:x:1000:1000::/home/bob:/bin/sh\n"); len(got) != 2 {
		t.Fatalf("uid0: %v", got)
	}
	if USBStoragePolicy("# x\ninstall usb-storage /bin/false\n") != "blocked" || USBStoragePolicy("blacklist pcspkr\n") != "allowed" {
		t.Fatal("usb policy")
	}
	apt := "Inst libssl3 [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])\n" +
		"Inst tzdata [2024a-0+deb12u1] (2024b-0+deb12u1 Debian:12.7/stable [all])\n"
	if CountSecurityUpgrades(apt) != 1 {
		t.Fatal("security upgrades")
	}
	if c := ParseSSHDConfig("permitrootlogin without-password\npasswordauthentication yes\n"); c["permitrootlogin"] != "without-password" {
		t.Fatalf("sshd -T: %v", c)
	}
}

func TestMacParsers(t *testing.T) {
	v := ParseSwVers("ProductName:\t\tmacOS\nProductVersion:\t\t26.5\nBuildVersion:\t\t25F71\n")
	if v["ProductVersion"] != "26.5" {
		t.Fatalf("sw_vers: %v", v)
	}
	if got := ParseLaunchctl("PID\tStatus\tLabel\n-\t0\tcom.apple.x\n412\t0\tcom.apple.Finder\n"); len(got) != 1 {
		t.Fatalf("launchctl: %v", got)
	}
	if got := ParseListening("tcp4 0 0 *.22 *.* LISTEN\ntcp4 0 0 127.0.0.1.8000 *.* LISTEN\n"); !reflect.DeepEqual(got, []int{22, 8000}) {
		t.Fatalf("netstat: %v", got)
	}
	if ParseMacFirewall("Firewall is enabled. (State = 1)") != "enabled" || ParseMacFirewall("Firewall is disabled. (State = 0)") != "disabled" {
		t.Fatal("mac firewall")
	}
}

func TestWindowsMapping(t *testing.T) {
	os, err := MapWindowsOS(json.RawMessage(`{"caption":"Microsoft Windows 10 Home","build":"19045","ubr":6466,"displayVersion":"22H2","productType":1}`))
	if err != nil || os["product"] != "Windows 10 Home" || os["build"] != "19045.6466" || os["server"] != false {
		t.Fatalf("os: %v %v", os, err)
	}
	fw, _ := MapWindowsFirewall(json.RawMessage(`[{"name":"Domain","enabled":true,"inbound":"NotConfigured"},{"name":"Public","enabled":false,"inbound":"NotConfigured"}]`))
	if fw["state"] != "partial" || fw["defaultInbound"] != "block" {
		t.Fatalf("firewall: %v", fw)
	}
	one, _ := MapWindowsFirewall(json.RawMessage(`{"name":"Domain","enabled":true,"inbound":"Block"}`))
	if one["state"] != "enabled" {
		t.Fatalf("single profile: %v", one)
	}
	if _, err := MapWindowsAntivirus(json.RawMessage(`{"defender":null,"securityCenter":[]}`)); err == nil {
		t.Fatal("no antivirus data must be an error (UNKNOWN), not 'stopped'")
	}
	av, _ := MapWindowsAntivirus(json.RawMessage(`{"defender":null,"securityCenter":{"name":"Sophos","state":266240}}`))
	if av["state"] != "running" {
		t.Fatalf("security center: %v", av)
	}
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	hf := MapWindowsHotfixes(json.RawMessage(`[{"id":"KB5066791","installedOn":"2026-10-15"},{"id":"KB5065429","installedOn":"2026-09-10"}]`), now)
	if hf["last_installed_days"] != 21 || len(hf["installed"].([]string)) != 2 {
		t.Fatalf("hotfixes: %v", hf)
	}
	adm := MapWindowsAdmins(json.RawMessage(`[{"name":"PC\\Administrator","enabled":false},{"name":"PC\\admin","enabled":true},{"name":"PLANT\\Domain Admins","class":"Group"}]`))
	if adm["enabled_count"] != 2 {
		t.Fatalf("admins: %v", adm)
	}
	na := ParseNetAccounts("Minimum password length:                              8\nMaximum password age (days):                         42\nLockout threshold:                                    Never\n")
	if na["min_length"] != 8 || na["max_age_days"] != 42 || na["lockout_threshold"] != 0 {
		t.Fatalf("net accounts: %v", na)
	}
	if v, ok := ParseSeceditComplexity("[System Access]\nPasswordComplexity = 1\n"); !ok || !v {
		t.Fatal("secedit")
	}
	csv := "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\n" +
		"PC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,\n"
	if ParseAuditpolLogon(csv) != "success_and_failure" {
		t.Fatal("auditpol")
	}
}
