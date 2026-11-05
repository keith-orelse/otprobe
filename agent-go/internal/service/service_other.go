//go:build !linux && !windows

package service

import (
	"context"
	"errors"
	"os/signal"
	"syscall"
)

var errUnsupported = errors.New("service installation is not supported on this platform (run in the foreground)")

func Install(exe, cfg, stateDir string) error { return errUnsupported }
func Uninstall() error                         { return errUnsupported }
func Start() error                             { return errUnsupported }
func Stop() error                              { return errUnsupported }
func Status() (string, error)                  { return "not supported", nil }
func DisableSelf()                             {}

func RunService(run func(ctx context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return run(ctx)
}
