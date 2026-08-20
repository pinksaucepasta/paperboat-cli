//go:build windows && paperboat_native_e2e

package execprocess

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func nativeWindowsExecManager(t *testing.T, root string) *Manager {
	t.Helper()
	baseEnvironment := []string{
		"PATH=" + os.Getenv("PATH"),
		"PATHEXT=" + os.Getenv("PATHEXT"),
		"SystemRoot=" + os.Getenv("SystemRoot"),
		"TEMP=" + os.Getenv("TEMP"),
		"TMP=" + os.Getenv("TMP"),
		"WINDIR=" + os.Getenv("WINDIR"),
	}
	manager, err := New(Config{
		WorkspaceRoot: root, BaseEnvironment: baseEnvironment, MaximumActive: 4,
		MaximumOperations: 128, ReplayBytes: 64 << 10, ChunkBytes: 1024,
		CancelGrace: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func nativeWindowsPowerShell(t *testing.T) string {
	t.Helper()
	path := filepath.Join(os.Getenv("WINDIR"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNativeWindowsExecRaceFreeStartStreamsEnvironmentCWDAndExit(t *testing.T) {
	root := t.TempDir()
	manager := nativeWindowsExecManager(t, root)
	powershell := nativeWindowsPowerShell(t)
	for index := range 25 {
		execution, replay, err := manager.Start(context.Background(), Request{
			OperationID: fmt.Sprintf("operation_windows_%02d", index),
			Argv: []string{powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
				`[Console]::Out.Write($PWD.Path + '|' + $env:PB_VALUE); [Console]::Error.Write('error'); exit 7`},
			CWD: root, Environment: map[string]string{"PB_VALUE": "a b"},
		})
		if err != nil || replay {
			t.Fatalf("iteration=%d replay=%v err=%v", index, replay, err)
		}
		snapshot, err := execution.Wait(context.Background())
		if err != nil || snapshot.State != StateExited || snapshot.Result == nil || snapshot.Result.Code != 7 {
			t.Fatalf("iteration=%d snapshot=%#v err=%v", index, snapshot, err)
		}
		var stdout, stderr strings.Builder
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		for sequence := uint64(1); ; sequence++ {
			event, nextErr := execution.Next(ctx, sequence)
			if errors.Is(nextErr, io.EOF) {
				break
			}
			if nextErr != nil {
				cancel()
				t.Fatal(nextErr)
			}
			if event.Stream == "stdout" {
				stdout.Write(event.Data)
			} else if event.Stream == "stderr" {
				stderr.Write(event.Data)
			}
		}
		cancel()
		if !strings.EqualFold(strings.Split(stdout.String(), "|")[0], root) || !strings.HasSuffix(stdout.String(), "|a b") || stderr.String() != "error" {
			t.Fatalf("iteration=%d stdout=%q stderr=%q", index, stdout.String(), stderr.String())
		}
	}
}
