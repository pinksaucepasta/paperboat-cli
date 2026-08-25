//go:build windows

package managedssh

// WindowsInstalledAgentPipe is the agent endpoint written to the Windows
// local daemon's managed OpenSSH configuration.
const WindowsInstalledAgentPipe = `\\.\pipe\Paperboat-SSH-Agent`

// InstalledAgentSocket returns the agent endpoint written to the local
// daemon's managed OpenSSH configuration.
func InstalledAgentSocket(_ string) string {
	return WindowsInstalledAgentPipe
}
