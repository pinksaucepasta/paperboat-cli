//go:build darwin || linux

package managedssh

import "testing"

func TestInstalledAgentSocketUsesRuntimeDirectory(t *testing.T) {
	const runtimeDirectory = "/var/run/paperboat-test"
	const want = "/var/run/paperboat-test/paperboat-ssh-agent.sock"
	if got := InstalledAgentSocket(runtimeDirectory); got != want {
		t.Fatalf("InstalledAgentSocket() = %q, want %q", got, want)
	}
}
