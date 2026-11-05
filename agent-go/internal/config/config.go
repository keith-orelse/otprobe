// Package config loads and saves the agent configuration (agent.json). The install script writes it with the
// server URL, the pinned CA fingerprint and a one-time enrollment token; after enrollment the token is removed and
// the agent's own credential is stored instead. The file is readable by SYSTEM/Administrators (Windows) or root
// (0600, Linux/macOS) only.
package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

type Config struct {
	ServerURL       string `json:"serverUrl"`
	CASHA256        string `json:"caSha256,omitempty"`        // pinned OTProbe CA (SHA-256 of the DER certificate)
	EnrollmentToken string `json:"enrollmentToken,omitempty"` // one-time; wiped after enrollment
	DeploymentID    string `json:"deploymentId,omitempty"`
	Profile         string `json:"profile,omitempty"` // windows-workstation, windows-server, linux-host, ...
	AgentID         string `json:"agentId,omitempty"`
	Credential      string `json:"credential,omitempty"`
	Insecure        bool   `json:"insecure,omitempty"` // plain HTTP to a lab server; never set by install scripts

	path string
}

// DefaultPath is where install scripts put agent.json.
func DefaultPath() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "OTProbe", "agent.json")
	case "darwin":
		return "/Library/Application Support/OTProbe/agent.json"
	default:
		return "/etc/otprobe/agent.json"
	}
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{path: path}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, err
	}
	if c.ServerURL == "" {
		return nil, errors.New("agent.json: serverUrl is required")
	}
	return c, nil
}

// Save writes atomically (temp file + rename) with owner-only permissions.
func (c *Config) Save() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

func (c *Config) Path() string { return c.path }

func (c *Config) Enrolled() bool { return c.AgentID != "" && c.Credential != "" }
