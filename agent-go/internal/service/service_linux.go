//go:build linux

package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

const unitPath = "/etc/systemd/system/otprobe-agent.service"
const sysvPath = "/etc/init.d/otprobe-agent"

// Hardened unit: low priority, capped CPU and memory, no new privileges, read-only system.
const unit = `[Unit]
Description=%s
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s run --config %s
Restart=on-failure
RestartSec=10
Nice=10
IOSchedulingClass=idle
CPUQuota=20%%
MemoryMax=128M
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
ReadWritePaths=%s

[Install]
WantedBy=multi-user.target
`

const sysv = `#!/bin/sh
### BEGIN INIT INFO
# Provides:          otprobe-agent
# Required-Start:    $network
# Required-Stop:     $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       %s
### END INIT INFO
case "$1" in
  start) nice -n 10 %s run --config %s >>/var/log/otprobe-agent.log 2>&1 & echo $! > /var/run/otprobe-agent.pid ;;
  stop) [ -f /var/run/otprobe-agent.pid ] && kill "$(cat /var/run/otprobe-agent.pid)" && rm -f /var/run/otprobe-agent.pid ;;
  status) [ -f /var/run/otprobe-agent.pid ] && kill -0 "$(cat /var/run/otprobe-agent.pid)" 2>/dev/null && echo running || { echo stopped; exit 3; } ;;
  *) echo "usage: $0 {start|stop|status}"; exit 1 ;;
esac
`

func systemd() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

func Install(exe, cfg, stateDir string) error {
	if systemd() {
		if err := os.WriteFile(unitPath, []byte(fmt.Sprintf(unit, Description, exe, cfg, stateDir)), 0o644); err != nil {
			return err
		}
		if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
			return err
		}
		return exec.Command("systemctl", "enable", "otprobe-agent").Run()
	}
	if err := os.WriteFile(sysvPath, []byte(fmt.Sprintf(sysv, Description, exe, cfg)), 0o755); err != nil {
		return err
	}
	for _, tool := range [][]string{{"update-rc.d", "otprobe-agent", "defaults"}, {"chkconfig", "--add", "otprobe-agent"},
		{"rc-update", "add", "otprobe-agent", "default"}} {
		if exec.Command(tool[0], tool[1:]...).Run() == nil {
			break
		}
	}
	return nil
}

func Uninstall() error {
	_ = Stop()
	if systemd() {
		_ = exec.Command("systemctl", "disable", "otprobe-agent").Run()
		_ = os.Remove(unitPath)
		return exec.Command("systemctl", "daemon-reload").Run()
	}
	_ = os.Remove(sysvPath)
	return nil
}

func Start() error {
	if systemd() {
		return exec.Command("systemctl", "start", "otprobe-agent").Run()
	}
	return exec.Command(sysvPath, "start").Run()
}

func Stop() error {
	if systemd() {
		return exec.Command("systemctl", "stop", "otprobe-agent").Run()
	}
	return exec.Command(sysvPath, "stop").Run()
}

func Status() (string, error) {
	cmd := exec.Command(sysvPath, "status")
	if systemd() {
		cmd = exec.Command("systemctl", "is-active", "otprobe-agent")
	}
	out, _ := cmd.Output()
	return string(out), nil
}

// DisableSelf keeps a revoked agent from starting again until it is reinstalled.
func DisableSelf() {
	if systemd() {
		_ = exec.Command("systemctl", "disable", "otprobe-agent").Run()
	}
}

// RunService runs the agent until SIGTERM/SIGINT.
func RunService(run func(ctx context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return run(ctx)
}
