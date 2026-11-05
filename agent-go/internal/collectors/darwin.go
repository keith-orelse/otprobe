//go:build darwin

package collectors

import (
	"context"
	"path/filepath"
	"strings"
)

// macOS: a smaller set (no macOS baseline policy yet). Used for development and as the base for a later macOS build.
func platform() []Collector {
	return []Collector{
		{"os", "os", darwinOS},
		{"firewall", "firewall", darwinFirewall},
		{"software", "software", darwinSoftware},
		{"services", "services", darwinServices},
	}
}

func darwinOS(ctx context.Context) (interface{}, error) {
	out, err := run(ctx, "sw_vers")
	if err != nil {
		return nil, err
	}
	v := ParseSwVers(out)
	kernel, _ := run(ctx, "uname", "-r")
	return map[string]interface{}{"family": "macos", "name": v["ProductName"] + " " + v["ProductVersion"],
		"product": v["ProductName"], "version": v["ProductVersion"], "build": v["BuildVersion"],
		"kernel": strings.TrimSpace(kernel)}, nil
}

func darwinFirewall(ctx context.Context) (interface{}, error) {
	out, err := run(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
	if err != nil {
		return nil, err
	}
	state := ParseMacFirewall(out)
	if state == "" {
		return nil, errNoData
	}
	return map[string]interface{}{"state": state}, nil
}

func darwinSoftware(ctx context.Context) (interface{}, error) {
	apps, _ := filepath.Glob("/Applications/*.app")
	var out []map[string]string
	for _, a := range apps {
		ver, _ := run(ctx, "defaults", "read", filepath.Join(a, "Contents", "Info"), "CFBundleShortVersionString")
		out = append(out, map[string]string{"name": strings.TrimSuffix(filepath.Base(a), ".app"),
			"version": strings.TrimSpace(ver)})
	}
	return map[string]interface{}{"installed": out}, nil
}

func darwinServices(ctx context.Context) (interface{}, error) {
	out, err := run(ctx, "launchctl", "list")
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"running": ParseLaunchctl(out)}, nil
}

func listeningPorts(ctx context.Context) ([]int, error) {
	out, err := run(ctx, "netstat", "-anp", "tcp")
	if err != nil {
		return nil, err
	}
	return ParseListening(out), nil
}

func Fingerprint() string {
	out, _ := run(context.Background(), "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	uuid := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "IOPlatformUUID") {
			if i := strings.LastIndex(line, "\""); i > 0 {
				parts := strings.Split(line, "\"")
				if len(parts) >= 4 {
					uuid = parts[3]
				}
			}
		}
	}
	return hashParts(uuid, Hostname())
}
