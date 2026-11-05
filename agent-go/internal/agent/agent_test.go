package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"otprobe/agent/internal/config"
	"otprobe/agent/internal/transport"
)

// fakeServer implements the agent protocol of /api/v1 (enroll, heartbeat, tasks, evidence).
type fakeServer struct {
	mu         sync.Mutex
	enrolled   map[string]interface{}
	heartbeats int
	tasks      []transport.Task
	evidence   map[string]interface{}
	revoke     bool
}

func (f *fakeServer) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/enroll", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewDecoder(r.Body).Decode(&f.enrolled)
		if f.enrolled["enrollmentToken"] != "enr_good" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"agentId": "ag1", "agentCredential": "agt_secret",
			"heartbeatIntervalSec": 0.05, "taskPollWaitSec": 0})
	})
	mux.HandleFunc("/api/v1/agents/ag1/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer agt_secret" || f.revoke {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			f.heartbeats++
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/tasks"):
			_ = json.NewEncoder(w).Encode(f.tasks)
			f.tasks = nil
		case strings.HasSuffix(r.URL.Path, "/evidence"):
			_ = json.NewDecoder(r.Body).Decode(&f.evidence)
			if r.Header.Get("X-Correlation-ID") != "corr-1" {
				t.Errorf("correlation id not propagated")
			}
			w.WriteHeader(http.StatusAccepted)
		}
	})
	return mux
}

func newAgent(t *testing.T, url string) (*Agent, *config.Config) {
	path := filepath.Join(t.TempDir(), "agent.json")
	_ = os.WriteFile(path, []byte(`{"serverUrl":"`+url+`","enrollmentToken":"enr_good","profile":"linux-host","insecure":true}`), 0o600)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.logf = t.Logf
	a.Hostname = func() string { return "hmi-line1" }
	a.HostPrint = func() string { return "fp" }
	a.Collect = func(ctx context.Context, names []string) (map[string]interface{}, map[string]string) {
		return map[string]interface{}{"firewall": map[string]interface{}{"state": "enabled"}},
			map[string]string{"firewall": "ok", "usb": "error: not available on this platform"}
	}
	return a, cfg
}

func TestEnrollHeartbeatTaskEvidenceRevoke(t *testing.T) {
	f := &fakeServer{tasks: []transport.Task{
		{TaskID: "t0", Kind: "RUN_COMMAND", CorrelationID: "corr-0"},
		{TaskID: "t1", Kind: "RUN_ASSESSMENT", CorrelationID: "corr-1",
			Payload: map[string]interface{}{"collectors": []interface{}{"firewall", "usb"}}}}}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	a, cfg := newAgent(t, srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for {
		f.mu.Lock()
		ok := f.evidence != nil && f.heartbeats >= 2
		f.mu.Unlock()
		if ok || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.mu.Lock()
	if f.enrolled["os"] == "" || f.enrolled["hostname"] != "hmi-line1" || f.enrolled["profile"] != "linux-host" {
		t.Errorf("enroll request: %v", f.enrolled)
	}
	if f.evidence == nil || f.evidence["schemaVersion"] != "1.1" || f.evidence["firewall"] == nil {
		t.Fatalf("evidence: %v", f.evidence)
	}
	if st := f.evidence["collectors"].(map[string]interface{}); st["usb"] == "ok" {
		t.Errorf("failed collector must be reported as error: %v", st)
	}
	f.revoke = true
	f.mu.Unlock()

	saved, _ := config.Load(cfg.Path())
	if saved.EnrollmentToken != "" || saved.Credential != "agt_secret" {
		t.Fatalf("token must be wiped and credential saved: %+v", saved)
	}
	if err := <-done; !errors.Is(err, transport.ErrRevoked) {
		t.Fatalf("revoked credential must stop the agent, got %v", err)
	}
}

func TestUnsupportedTaskIsRefused(t *testing.T) {
	a, _ := newAgent(t, "http://127.0.0.1:1")
	err := a.handle(context.Background(), transport.Task{TaskID: "x", Kind: "RUN_COMMAND"})
	if err == nil || !strings.Contains(err.Error(), "TASK_TYPE_UNSUPPORTED") {
		t.Fatalf("expected refusal, got %v", err)
	}
}
