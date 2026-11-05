// Package service installs the agent as an OS service and runs it under the service manager. The agent binary
// registers itself (install scripts call `otprobe-agent install`), so scripts stay short and the same on every
// supported OS version.
package service

const (
	Name        = "OTProbeAgent"
	DisplayName = "OTProbe Agent"
	Description = "OTProbe read-only compliance agent (outbound HTTPS only, no listening ports)"
)
