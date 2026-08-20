//go:build windows

package hostservice

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsUpdateDiagnosticsRequiresRunningServiceAndMatchingState(t *testing.T) {
	root := t.TempDir()
	diagnostics := &windowsUpdateDiagnostics{
		statePath: filepath.Join(root, "service-state.json"),
		machineID: "machine-1",
		running:   func() bool { return true },
	}
	if got := diagnostics.UpdateHealth(); got != "recovery_required" {
		t.Fatalf("missing state health = %q", got)
	}
	body := []byte(`{"schema":"paperboat.windows-updated/v1","machine_id":"machine-1","recovered_at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}`)
	if err := os.WriteFile(diagnostics.statePath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := diagnostics.UpdateHealth(); got != "healthy" {
		t.Fatalf("valid state health = %q", got)
	}
	diagnostics.running = func() bool { return false }
	if got := diagnostics.UpdateHealth(); got != "recovery_required" {
		t.Fatalf("stopped service health = %q", got)
	}
}
