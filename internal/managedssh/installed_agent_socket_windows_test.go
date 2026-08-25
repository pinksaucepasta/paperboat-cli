//go:build windows

package managedssh

import "testing"

func TestInstalledAgentSocketUsesWindowsNamedPipe(t *testing.T) {
	const want = `\\.\pipe\Paperboat-SSH-Agent`
	if got := InstalledAgentSocket(`C:\Users\Pujan\AppData\Local\paperboat\run`); got != want {
		t.Fatalf("InstalledAgentSocket() = %q, want %q", got, want)
	}
}
