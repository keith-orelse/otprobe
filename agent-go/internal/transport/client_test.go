package transport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func pinOf(srv *httptest.Server) string {
	sum := sha256.Sum256(srv.Certificate().Raw)
	return hex.EncodeToString(sum[:])
}

func TestPinnedTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c, _ := New(srv.URL, pinOf(srv), false)
	c.SetCredential("a1", "agt_x")
	if err := c.Heartbeat(context.Background(), Heartbeat{}); err != nil {
		t.Fatalf("pinned CA must be accepted: %v", err)
	}
	wrong, _ := New(srv.URL, "00"+pinOf(srv)[2:], false)
	wrong.SetCredential("a1", "agt_x")
	if err := wrong.Heartbeat(context.Background(), Heartbeat{}); err == nil {
		t.Fatal("a server whose chain lacks the pinned CA must be refused")
	}
}

func TestPlainHTTPNeedsInsecure(t *testing.T) {
	if _, err := New("http://otprobe.local", "", false); err == nil {
		t.Fatal("plain HTTP must be refused unless explicitly allowed")
	}
}

func TestRevokedCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"title":"Agent credential revoked"}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "", true)
	c.SetCredential("a1", "agt_x")
	if err := c.Heartbeat(context.Background(), Heartbeat{}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("401 must map to ErrRevoked, got %v", err)
	}
}
