// Package transport is the agent's only network code: outbound HTTPS to the OTProbe server. TLS is accepted only
// when the server's chain contains the pinned OTProbe CA (caSha256), so a system-trusted certificate for another
// server is refused too. The agent never listens on a port.
package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrRevoked means the server rejected the credential (401): the agent must stop and stay stopped.
var ErrRevoked = errors.New("agent credential rejected by server")

type Client struct {
	base string
	http *http.Client
	cred string
	ID   string
}

type EnrollRequest struct {
	EnrollmentToken string `json:"enrollmentToken"`
	Hostname        string `json:"hostname"`
	HostFingerprint string `json:"hostFingerprint"`
	AgentVersion    string `json:"agentVersion"`
	OS              string `json:"os,omitempty"`
	Arch            string `json:"arch,omitempty"`
	Variant         string `json:"variant,omitempty"`
	Profile         string `json:"profile,omitempty"`
}

type EnrollResponse struct {
	AgentID              string  `json:"agentId"`
	AgentCredential      string  `json:"agentCredential"`
	HeartbeatIntervalSec float64 `json:"heartbeatIntervalSec"`
	TaskPollWaitSec      int     `json:"taskPollWaitSec"`
}

type Heartbeat struct {
	Seq          int       `json:"seq"`
	AgentTime    time.Time `json:"agentTime"`
	AgentVersion string    `json:"agentVersion"`
	MemMB        float64   `json:"memMb,omitempty"`
	QueueDepth   int       `json:"queueDepth"`
}

type Task struct {
	TaskID        string                 `json:"taskId"`
	Kind          string                 `json:"kind"`
	CorrelationID string                 `json:"correlationId"`
	Deadline      string                 `json:"deadline"`
	Payload       map[string]interface{} `json:"payload"`
}

// New builds a client. caSHA256 = "" means normal system trust (lab only); insecure allows plain http://.
func New(serverURL, caSHA256 string, insecure bool) (*Client, error) {
	base := strings.TrimRight(serverURL, "/")
	if strings.HasPrefix(base, "http://") && !insecure {
		return nil, errors.New("refusing plain HTTP: set insecure only for a lab server")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caSHA256 != "" {
		want := strings.ToLower(strings.ReplaceAll(caSHA256, ":", ""))
		tlsCfg.InsecureSkipVerify = true // replaced by VerifyConnection below: chain must lead to the pinned CA
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error { return verifyPinned(cs, want) }
	}
	tr := &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment,
		ResponseHeaderTimeout: 60 * time.Second, MaxIdleConns: 2, IdleConnTimeout: 90 * time.Second}
	return &Client{base: base + "/api/v1", http: &http.Client{Transport: tr, Timeout: 90 * time.Second}}, nil
}

// verifyPinned accepts the connection only if the presented chain verifies against the pinned CA certificate.
func verifyPinned(cs tls.ConnectionState, want string) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("server presented no certificate")
	}
	pool := x509.NewCertPool()
	var pinned *x509.Certificate
	for _, c := range cs.PeerCertificates {
		sum := sha256.Sum256(c.Raw)
		if hex.EncodeToString(sum[:]) == want {
			pinned = c
		}
	}
	if pinned == nil {
		return errors.New("server certificate chain does not contain the pinned OTProbe CA")
	}
	pool.AddCert(pinned)
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter})
	return err
}

func (c *Client) SetCredential(agentID, credential string) { c.ID, c.cred = agentID, credential }

func (c *Client) do(ctx context.Context, method, path string, body interface{}, headers map[string]string,
	out interface{}) (int, error) {
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "otprobe-agent")
	if c.cred != "" {
		req.Header.Set("Authorization", "Bearer "+c.cred)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == http.StatusUnauthorized && c.cred != "" {
		return resp.StatusCode, ErrRevoked
	}
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, problemDetail(data))
	}
	if out != nil && len(data) > 0 {
		return resp.StatusCode, json.Unmarshal(data, out)
	}
	return resp.StatusCode, nil
}

func problemDetail(data []byte) string {
	var p struct{ Title, Detail string }
	if json.Unmarshal(data, &p) == nil && (p.Title != "" || p.Detail != "") {
		return strings.TrimSpace(p.Title + ": " + p.Detail)
	}
	if len(data) > 200 {
		data = data[:200]
	}
	return string(data)
}

func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (*EnrollResponse, error) {
	var out EnrollResponse
	if _, err := c.do(ctx, http.MethodPost, "/agents/enroll", req, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Heartbeat(ctx context.Context, hb Heartbeat) error {
	_, err := c.do(ctx, http.MethodPost, "/agents/"+c.ID+"/heartbeat", hb, nil, nil)
	return err
}

func (c *Client) PollTasks(ctx context.Context, waitSec int) ([]Task, error) {
	var tasks []Task
	_, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/agents/%s/tasks?waitSec=%d", c.ID, waitSec), nil, nil, &tasks)
	return tasks, err
}

func (c *Client) UploadEvidence(ctx context.Context, task Task, evidence map[string]interface{}) error {
	_, err := c.do(ctx, http.MethodPost, "/agents/"+c.ID+"/tasks/"+task.TaskID+"/evidence", evidence,
		map[string]string{"X-Correlation-ID": task.CorrelationID}, nil)
	return err
}
