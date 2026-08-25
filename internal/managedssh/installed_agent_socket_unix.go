//go:build darwin || linux

package managedssh

import "path/filepath"

// InstalledAgentSocket returns the agent endpoint written to the local
// daemon's managed OpenSSH configuration.
func InstalledAgentSocket(runtimeDirectory string) string {
	return filepath.Join(filepath.Clean(runtimeDirectory), "paperboat-ssh-agent.sock")
}
