// Package collectors gathers read-only evidence about the host the agent runs on. Collectors COLLECT; they never
// judge: PASS/FAIL is decided on the server by the rules (docs/RULES.md). Every command is a fixed string compiled
// into the binary, run without a shell and with a timeout. Nothing in a task can change which commands run.
package collectors

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"time"
)

// Func returns one evidence section (e.g. the value under "firewall"), or an error.
type Func func(ctx context.Context) (interface{}, error)

type Collector struct {
	Name string // as requested by the server's task ("firewall", "patches", ...)
	Key  string // evidence section it fills
	Fn   Func
}

const perCollectorTimeout = 45 * time.Second

// Available lists the collectors compiled in for this platform.
func Available() map[string]Collector {
	out := map[string]Collector{}
	for _, c := range append(platform(), common()...) {
		out[c.Name] = c
	}
	return out
}

// Names returns the compiled-in collector names, sorted.
func Names() []string {
	var out []string
	for n := range Available() {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Run executes the requested collectors one after another (low impact) and returns the evidence sections plus a
// status per collector ("ok" or "error: ..."). A failed collector's section is absent, so the server's rule for it
// evaluates to UNKNOWN, never to FAIL.
func Run(ctx context.Context, names []string) (map[string]interface{}, map[string]string) {
	avail := Available()
	sections := map[string]interface{}{}
	status := map[string]string{}
	for _, name := range names {
		c, ok := avail[name]
		if !ok {
			status[name] = "error: not available on this platform"
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, perCollectorTimeout)
		value, err := safeCall(cctx, c.Fn)
		cancel()
		if err != nil {
			status[name] = "error: " + err.Error()
			continue
		}
		if value != nil {
			sections[c.Key] = value
		}
		status[name] = "ok"
	}
	return sections, status
}

func safeCall(ctx context.Context, fn Func) (v interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("collector panicked: %v", r)
		}
	}()
	return fn(ctx)
}

// run executes a fixed command (no shell) and returns stdout.
func run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return "", errors.New("timed out")
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(out) > 0 {
			return string(out), nil // many tools exit non-zero but still print what we need
		}
		return "", fmt.Errorf("%s: %v", name, err)
	}
	return string(out), nil
}
