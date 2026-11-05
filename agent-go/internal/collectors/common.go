package collectors

import (
	"context"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

// Version is set at build time: -ldflags "-X otprobe/agent/internal/collectors.Version=1.2.0".
var Version = "dev"

var started = time.Now()

func common() []Collector {
	return []Collector{
		{"agent", "agent", agentHealth},
		{"network", "network", network},
	}
}

func agentHealth(ctx context.Context) (interface{}, error) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return map[string]interface{}{"health": "healthy", "version": Version,
		"uptime_sec": int(time.Since(started).Seconds()), "mem_mb": mem.Sys / (1 << 20),
		"platform": runtime.GOOS + "/" + runtime.GOARCH}, nil
}

// network: interfaces with an address (link-local 169.254.x.x and loopback skipped) and listening TCP ports.
func network(ctx context.Context) (interface{}, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []map[string]interface{}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil || ipn.IP.IsLinkLocalUnicast() {
				continue
			}
			prefix, _ := ipn.Mask.Size()
			out = append(out, map[string]interface{}{"name": i.Name, "ip": ipn.IP.String(), "prefix": prefix,
				"mac": strings.ToUpper(i.HardwareAddr.String())})
		}
	}
	section := map[string]interface{}{"interfaces": out}
	if ports, err := listeningPorts(ctx); err == nil {
		section["listening"] = ports
	}
	return section, nil
}

// Hostname and Fingerprint identify the host at enrollment.
func Hostname() string {
	h, _ := os.Hostname()
	return h
}
