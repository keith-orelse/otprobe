//go:build !linux && !windows && !darwin

package collectors

import "context"

func platform() []Collector { return nil }

func listeningPorts(ctx context.Context) ([]int, error) { return nil, errNoData }

func Fingerprint() string { return hashParts(Hostname()) }
