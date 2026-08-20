//go:build darwin || linux

package managedssh

import "path/filepath"

func ownerAgentSocket(runtimeDirectory string) (string, error) {
	return filepath.Join(filepath.Clean(runtimeDirectory), "paperboat-ssh-agent.sock"), nil
}
