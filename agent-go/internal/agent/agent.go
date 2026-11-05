// Package agent is the agent's main loop: enroll once, then heartbeat, long-poll for tasks and upload evidence.
// Tasks are a closed set (RUN_ASSESSMENT); there is no task that runs a command (decision R4).
package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"runtime"
	"sync/atomic"
	"time"

	"otprobe/agent/internal/collectors"
	"otprobe/agent/internal/config"
	"otprobe/agent/internal/transport"
)

// Variant is set at build time for the legacy (Go 1.20) builds.
var Variant = "modern"

const assessmentTimeout = 120 * time.Second

type Agent struct {
	cfg       *config.Config
	client    *transport.Client
	interval  time.Duration
	pollWait  int
	queue     int32
	logf      func(format string, args ...interface{})
	Collect   func(ctx context.Context, names []string) (map[string]interface{}, map[string]string)
	Hostname  func() string
	HostPrint func() string
}

func New(cfg *config.Config) (*Agent, error) {
	c, err := transport.New(cfg.ServerURL, cfg.CASHA256, cfg.Insecure)
	if err != nil {
		return nil, err
	}
	return &Agent{cfg: cfg, client: c, interval: 10 * time.Second, pollWait: 20, logf: log.Printf,
		Collect: collectors.Run, Hostname: collectors.Hostname, HostPrint: collectors.Fingerprint}, nil
}

// Run blocks until ctx is cancelled (service stop) or the credential is revoked (returns transport.ErrRevoked).
func (a *Agent) Run(ctx context.Context) error {
	if err := a.ensureEnrolled(ctx); err != nil {
		return err
	}
	a.client.SetCredential(a.cfg.AgentID, a.cfg.Credential)
	errs := make(chan error, 2)
	go func() { errs <- a.heartbeatLoop(ctx) }()
	go func() { errs <- a.taskLoop(ctx) }()
	err := <-errs
	return err
}

func (a *Agent) ensureEnrolled(ctx context.Context) error {
	if a.cfg.Enrolled() {
		return nil
	}
	if a.cfg.EnrollmentToken == "" {
		return errors.New("not enrolled and no enrollment token in agent.json: reinstall the agent")
	}
	backoff := 5 * time.Second
	for {
		resp, err := a.client.Enroll(ctx, transport.EnrollRequest{
			EnrollmentToken: a.cfg.EnrollmentToken, Hostname: a.Hostname(), HostFingerprint: a.HostPrint(),
			AgentVersion: collectors.Version, OS: runtime.GOOS, Arch: runtime.GOARCH, Variant: Variant,
			Profile: a.cfg.Profile})
		if err == nil {
			a.cfg.AgentID, a.cfg.Credential, a.cfg.EnrollmentToken = resp.AgentID, resp.AgentCredential, ""
			if resp.HeartbeatIntervalSec > 0 {
				a.interval = time.Duration(resp.HeartbeatIntervalSec * float64(time.Second))
			}
			if resp.TaskPollWaitSec > 0 {
				a.pollWait = resp.TaskPollWaitSec
			}
			if err := a.cfg.Save(); err != nil {
				return fmt.Errorf("enrolled as %s but could not save the credential: %w", resp.AgentID, err)
			}
			a.logf("enrolled as agent %s", resp.AgentID)
			return nil
		}
		a.logf("enrollment failed: %v (retrying in %s)", err, backoff)
		if !sleep(ctx, backoff) {
			return ctx.Err()
		}
		if backoff < 2*time.Minute {
			backoff *= 2
		}
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context) error {
	seq := 0
	for {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		err := a.client.Heartbeat(ctx, transport.Heartbeat{Seq: seq, AgentTime: time.Now().UTC(),
			AgentVersion: collectors.Version, MemMB: float64(mem.Sys) / (1 << 20),
			QueueDepth: int(atomic.LoadInt32(&a.queue))})
		if errors.Is(err, transport.ErrRevoked) {
			return err
		}
		if err != nil && ctx.Err() == nil {
			a.logf("heartbeat %d failed: %v", seq, err)
		}
		seq++
		if !sleep(ctx, a.interval) {
			return ctx.Err()
		}
	}
}

func (a *Agent) taskLoop(ctx context.Context) error {
	for {
		tasks, err := a.client.PollTasks(ctx, a.pollWait)
		if errors.Is(err, transport.ErrRevoked) {
			return err
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			a.logf("task poll failed: %v", err)
			if !sleep(ctx, a.interval) {
				return ctx.Err()
			}
			continue
		}
		for _, t := range tasks {
			atomic.AddInt32(&a.queue, 1)
			err := a.handle(ctx, t)
			atomic.AddInt32(&a.queue, -1)
			if errors.Is(err, transport.ErrRevoked) {
				return err
			}
			if err != nil {
				a.logf("task %s: %v", t.TaskID, err)
			}
		}
	}
}

// handle runs one task. Only RUN_ASSESSMENT exists; anything else is refused and logged.
func (a *Agent) handle(ctx context.Context, t transport.Task) error {
	if t.Kind != "RUN_ASSESSMENT" {
		return fmt.Errorf("task type %q is not supported by this agent (TASK_TYPE_UNSUPPORTED)", t.Kind)
	}
	names := requestedCollectors(t.Payload)
	actx, cancel := context.WithTimeout(ctx, assessmentTimeout)
	defer cancel()
	sections, status := a.Collect(actx, names)
	evidence := map[string]interface{}{
		"schemaVersion": "1.1",
		"collectedAt":   time.Now().UTC().Format(time.RFC3339),
		"identity":      map[string]interface{}{"hostname": a.Hostname()},
		"platform":      map[string]interface{}{"os": runtime.GOOS, "arch": runtime.GOARCH, "variant": Variant},
		"profile":       a.cfg.Profile,
		"collectors":    status,
	}
	for k, v := range sections {
		evidence[k] = v
	}
	backoff := 2 * time.Second
	for attempt := 1; ; attempt++ {
		err := a.client.UploadEvidence(ctx, t, evidence)
		if err == nil || errors.Is(err, transport.ErrRevoked) || attempt == 5 {
			if err == nil {
				a.logf("task %s: evidence uploaded (%d sections)", t.TaskID, len(sections))
			}
			return err
		}
		a.logf("evidence upload attempt %d failed: %v", attempt, err)
		if !sleep(ctx, backoff) {
			return ctx.Err()
		}
		backoff *= 2
	}
}

func requestedCollectors(payload map[string]interface{}) []string {
	var names []string
	if list, ok := payload["collectors"].([]interface{}); ok {
		for _, n := range list {
			if s, ok := n.(string); ok {
				names = append(names, s)
			}
		}
	}
	if len(names) == 0 {
		names = collectors.Names()
	}
	return names
}

func sleep(ctx context.Context, d time.Duration) bool {
	jitter := time.Duration(rand.Int63n(int64(d)/10 + 1))
	t := time.NewTimer(d + jitter)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
