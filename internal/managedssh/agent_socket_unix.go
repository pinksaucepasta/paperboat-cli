//go:build darwin || linux

package managedssh

func ownerAgentSocket(runtimeDirectory string) (string, error) {
	return InstalledAgentSocket(runtimeDirectory), nil
}
