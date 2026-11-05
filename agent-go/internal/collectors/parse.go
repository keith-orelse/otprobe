package collectors

// Pure parsers for command output. They live in an untagged file so every platform's parsing is unit-tested on any
// build host (testdata/ holds recorded output from real systems).

import (
	"bufio"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- Linux ----------------------------------------------------------------------------------------------------------

func ParseOSRelease(text string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "="); i > 0 {
			out[line[:i]] = strings.Trim(line[i+1:], `"'`)
		}
	}
	return out
}

// ParsePackages reads `dpkg-query -W -f='${Package}\t${Version}\n'`, `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'`
// or `apk info -v` (name-version-rN).
func ParsePackages(text string) []map[string]string {
	apk := regexp.MustCompile(`^(.+?)-(\d[^-]*-r\d+)$`)
	var out []map[string]string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "WARNING") {
			continue
		}
		name, version := line, ""
		if i := strings.Index(line, "\t"); i >= 0 {
			name, version = line[:i], line[i+1:]
		} else if m := apk.FindStringSubmatch(line); m != nil {
			name, version = m[1], m[2]
		}
		out = append(out, map[string]string{"name": name, "version": version})
	}
	return out
}

// ParseSystemdRunning reads `systemctl list-units --type=service --state=running --no-legend --plain`.
func ParseSystemdRunning(text string) []map[string]string {
	var out []map[string]string
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.HasSuffix(f[0], ".service") {
			out = append(out, map[string]string{"name": strings.TrimSuffix(f[0], ".service"), "state": "running"})
		}
	}
	return out
}

// ParseListening reads `ss -Hltn`, Linux `netstat -ltn` or macOS `netstat -anp tcp`: local address = 4th column.
func ParseListening(text string) []int {
	seen := map[int]bool{}
	sep := regexp.MustCompile(`[:.]`)
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		listen := false
		for _, x := range f {
			if x == "LISTEN" {
				listen = true
			}
		}
		if !listen || len(f) < 4 {
			continue
		}
		parts := sep.Split(f[3], -1)
		if p, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
			seen[p] = true
		}
	}
	return sortedKeys(seen)
}

// ParseProcNetTCP reads /proc/net/tcp and /proc/net/tcp6: state 0A = LISTEN, port in hex after the colon.
func ParseProcNetTCP(text string) []int {
	seen := map[int]bool{}
	for _, line := range strings.Split(text, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 4 || f[3] != "0A" {
			continue
		}
		if i := strings.LastIndex(f[1], ":"); i >= 0 {
			if p, err := strconv.ParseInt(f[1][i+1:], 16, 32); err == nil {
				seen[int(p)] = true
			}
		}
	}
	return sortedKeys(seen)
}

// ParseLoginDefs returns PASS_MIN_LEN / PASS_MAX_DAYS etc. from /etc/login.defs.
func ParseKeyValues(text, sep string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var k, v string
		if sep == "" {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			k, v = f[0], f[1]
		} else if i := strings.Index(line, sep); i > 0 {
			k, v = strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:])
		} else {
			continue
		}
		out[k] = v
	}
	return out
}

// ParseSSHDConfig reads `sshd -T` (lower-case "key value" lines).
func ParseSSHDConfig(text string) map[string]string {
	return ParseKeyValues(text, "")
}

// ParseGroupMembers reads `getent group sudo wheel admin` lines: name:x:gid:user1,user2.
func ParseGroupMembers(text string) []string {
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		parts := strings.Split(strings.TrimSpace(line), ":")
		if len(parts) == 4 && parts[3] != "" {
			for _, m := range strings.Split(parts[3], ",") {
				seen[m] = true
			}
		}
	}
	return sortedStrings(seen)
}

// ParseUID0 lists accounts with UID 0 from /etc/passwd.
func ParseUID0(passwd string) []string {
	var out []string
	for _, line := range strings.Split(passwd, "\n") {
		p := strings.Split(line, ":")
		if len(p) >= 3 && p[2] == "0" {
			out = append(out, p[0])
		}
	}
	return out
}

// USBStoragePolicy reads modprobe configuration: "blacklist usb-storage" or "install usb-storage /bin/false".
func USBStoragePolicy(modprobe string) string {
	re := regexp.MustCompile(`(?m)^\s*(blacklist\s+usb[-_]storage|install\s+usb[-_]storage\s+/bin/(false|true))`)
	if re.MatchString(modprobe) {
		return "blocked"
	}
	return "allowed"
}

// CountSecurityUpgrades counts "Inst" lines from `apt-get -s upgrade` that come from a security pocket.
func CountSecurityUpgrades(simulated string) int {
	n := 0
	for _, line := range strings.Split(simulated, "\n") {
		if strings.HasPrefix(line, "Inst ") && strings.Contains(strings.ToLower(line), "security") {
			n++
		}
	}
	return n
}

// ---- macOS -----------------------------------------------------------------------------------------------------------

func ParseSwVers(text string) map[string]string { return ParseKeyValues(text, ":") }

// ParseLaunchctl reads `launchctl list` (PID Status Label); a numeric PID means the job is running.
func ParseLaunchctl(text string) []map[string]string {
	var out []map[string]string
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 {
			if _, err := strconv.Atoi(f[0]); err == nil {
				out = append(out, map[string]string{"name": f[2], "state": "running"})
			}
		}
	}
	return out
}

func ParseMacFirewall(text string) string {
	switch {
	case strings.Contains(text, "Firewall is enabled"), strings.Contains(text, "State = 1"),
		strings.Contains(text, "State = 2"):
		return "enabled"
	case strings.Contains(text, "Firewall is disabled"), strings.Contains(text, "State = 0"):
		return "disabled"
	}
	return ""
}

// ---- Windows ---------------------------------------------------------------------------------------------------------

// ParseNetAccounts reads `net accounts` (English output; other UI languages fall back to secedit values).
func ParseNetAccounts(text string) map[string]interface{} {
	out := map[string]interface{}{}
	num := func(v string) (int, bool) {
		if strings.EqualFold(strings.TrimSpace(v), "Never") || strings.EqualFold(strings.TrimSpace(v), "Unlimited") {
			return 0, true
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		return n, err == nil
	}
	for _, line := range strings.Split(text, "\n") {
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		k, v := strings.ToLower(strings.TrimSpace(line[:i])), line[i+1:]
		switch {
		case strings.HasPrefix(k, "minimum password length"):
			if n, ok := num(v); ok {
				out["min_length"] = n
			}
		case strings.HasPrefix(k, "maximum password age"):
			if n, ok := num(v); ok {
				out["max_age_days"] = n
			}
		case strings.HasPrefix(k, "lockout threshold"):
			if n, ok := num(v); ok {
				out["lockout_threshold"] = n
			}
		}
	}
	return out
}

// ParseSeceditComplexity reads PasswordComplexity from a `secedit /export /areas SECURITYPOLICY` file.
func ParseSeceditComplexity(text string) (bool, bool) {
	kv := ParseKeyValues(strings.ReplaceAll(text, "\x00", ""), "=")
	v, ok := kv["PasswordComplexity"]
	return v == "1", ok
}

// ParseAuditpolLogon reads `auditpol /get /subcategory:{0CCE9215-...} /r` (CSV; "Inclusion Setting" column).
func ParseAuditpolLogon(csv string) string {
	lines := strings.Split(strings.TrimSpace(csv), "\n")
	if len(lines) < 2 {
		return ""
	}
	header := strings.Split(lines[0], ",")
	col := -1
	for i, h := range header {
		if strings.EqualFold(strings.TrimSpace(h), "Inclusion Setting") {
			col = i
		}
	}
	if col < 0 {
		return ""
	}
	fields := strings.Split(lines[1], ",")
	if col >= len(fields) {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(fields[col])) {
	case "success and failure":
		return "success_and_failure"
	case "failure":
		return "failure"
	case "success":
		return "success"
	case "no auditing":
		return "no_auditing"
	}
	return ""
}

// ParseHotfixDays converts InstalledOn dates (yyyy-MM-dd) to days since the newest one.
func ParseHotfixDays(dates []string, now time.Time) (int, bool) {
	var newest time.Time
	for _, d := range dates {
		if t, err := time.Parse("2006-01-02", d); err == nil && t.After(newest) {
			newest = t
		}
	}
	if newest.IsZero() {
		return 0, false
	}
	return int(now.Sub(newest).Hours() / 24), true
}

// AsList normalises ConvertTo-Json output: a one-element array arrives as a bare object.
func AsList(raw json.RawMessage) []map[string]interface{} {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var list []map[string]interface{}
	if raw[0] == '[' {
		_ = json.Unmarshal(raw, &list)
		return list
	}
	var one map[string]interface{}
	if json.Unmarshal(raw, &one) == nil {
		return []map[string]interface{}{one}
	}
	return nil
}

// ---- helpers ---------------------------------------------------------------------------------------------------------

func sortedKeys(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func sortedStrings(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
