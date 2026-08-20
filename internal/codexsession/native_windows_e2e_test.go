//go:build windows && paperboat_native_e2e

package codexsession

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNativeWindowsCodexContract qualifies the supported native Codex binary
// Paperboat launches. It intentionally checks the remote app-server flags used
// by workflow.go, not only that an executable named codex exists.
func TestNativeWindowsCodexContract(t *testing.T) {
	path := os.Getenv("PAPERBOAT_WINDOWS_E2E_CODEX_PATH")
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".exe") {
		t.Fatal("PAPERBOAT_WINDOWS_E2E_CODEX_PATH must name an absolute native Codex .exe")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	got, err := version(ctx, path)
	if err != nil || got == "" {
		t.Fatalf("query native Codex version: version=%q error=%v", got, err)
	}
	output, err := exec.CommandContext(ctx, path, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("query native Codex contract: %v: %s", err, output)
	}
	help := string(output)
	for _, required := range []string{"--remote <ADDR>", "--remote-auth-token-env <ENV_VAR>", "-C, --cd <DIR>"} {
		if !strings.Contains(help, required) {
			t.Errorf("native Codex %s does not expose required option %q", got, required)
		}
	}
}
