//go:build windows && paperboat_native_e2e

package session

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/pty"
)

func nativeWindowsManager(t *testing.T) (*Manager, string) {
	t.Helper()
	root := t.TempDir()
	adapter, err := pty.NewAdapter(root)
	if err != nil {
		t.Fatal(err)
	}
	randomBytes := make([]byte, 128)
	for index := range randomBytes {
		randomBytes[index] = byte(index)
	}
	manager, err := NewManager(ManagerConfig{
		Launch:             func(command pty.Command) (PTYProcess, error) { return adapter.Start(command) },
		Random:             bytes.NewReader(randomBytes),
		HistoryBytes:       1 << 20,
		AttachmentBytes:    1 << 20,
		TerminationTimeout: 5 * time.Second,
		TerminationGrace:   250 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager, root
}

func nativeWindowsCommand(root string) pty.Command {
	shell := os.Getenv("ComSpec")
	if shell == "" {
		shell = `C:\Windows\System32\cmd.exe`
	}
	return pty.Command{
		Path:       shell,
		Args:       []string{"/D", "/Q"},
		CWD:        root,
		Dimensions: pty.Dimensions{Columns: 80, Rows: 24},
	}
}

func TestNativeWindowsManagerReplayReconnectResizeCancelAndCleanup(t *testing.T) {
	manager, root := nativeWindowsManager(t)
	created, err := manager.Create(context.Background(), CreateRequest{
		Name:    "native-windows",
		Command: nativeWindowsCommand(root),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Shutdown(shutdownCtx)
	})

	first, err := manager.Attach(created.ID, "first", 0)
	if err != nil {
		t.Fatal(err)
	}
	key := InputKey{ClientID: "native", AttachmentID: "first", Generation: created.Generation, InputID: "ready"}
	if decision, writeErr := manager.Write(created.ID, key, []byte("echo PB_READY\r\n")); writeErr != nil || decision.Status != InputAccepted {
		t.Fatalf("ready input decision=%+v err=%v", decision, writeErr)
	}
	readyOutput := collectNativeWindowsUntil(t, manager, created.ID, "first", "PB_READY")
	if !strings.Contains(readyOutput, "PB_READY") {
		t.Fatalf("ready output=%q", readyOutput)
	}

	if err := manager.Resize(created.ID, "first", pty.Dimensions{Columns: 101, Rows: 37}, time.Now()); err != nil {
		t.Fatal(err)
	}
	resized, err := manager.Snapshot(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if resized.Dimensions != (pty.Dimensions{Columns: 101, Rows: 37}) {
		t.Fatalf("dimensions=%+v", resized.Dimensions)
	}

	replayCursor := first.Replay.ToSequence
	if err := manager.Detach(created.ID, "first"); err != nil {
		t.Fatal(err)
	}
	reconnected, err := manager.Attach(created.ID, "second", replayCursor)
	if err != nil {
		t.Fatal(err)
	}
	var replay strings.Builder
	for _, event := range reconnected.Replay.Events {
		replay.Write(event.Data)
	}
	if !strings.Contains(replay.String(), "PB_READY") {
		t.Fatalf("replay from %d did not contain prior output: %q", replayCursor, replay.String())
	}

	key = InputKey{ClientID: "native", AttachmentID: "second", Generation: created.Generation, InputID: "long-running"}
	if _, err := manager.Write(created.ID, key, []byte("ping -t 127.0.0.1 >nul\r\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := manager.Signal(created.ID, created.Generation, pty.Interrupt); err != nil {
		t.Fatal(err)
	}
	key.InputID = "after-cancel"
	if _, err := manager.Write(created.ID, key, []byte("echo PB_AFTER_CANCEL\r\n")); err != nil {
		t.Fatal(err)
	}
	if output := collectNativeWindowsUntil(t, manager, created.ID, "second", "PB_AFTER_CANCEL"); !strings.Contains(output, "PB_AFTER_CANCEL") {
		t.Fatalf("post-cancel output=%q", output)
	}

	closed, err := manager.Close(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if closed.State != Closed {
		t.Fatalf("close state=%s", closed.State)
	}
	if err := manager.Delete(created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Snapshot(created.ID); err != ErrSessionUnknown {
		t.Fatalf("snapshot after delete err=%v", err)
	}
}

func collectNativeWindowsUntil(t *testing.T, manager *Manager, sessionID, attachmentID, marker string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var output strings.Builder
	for {
		event, err := manager.WaitNext(ctx, sessionID, attachmentID)
		if err != nil {
			t.Fatalf("output=%q missing %q: %v", output.String(), marker, err)
		}
		output.Write(event.Data)
		if strings.Contains(output.String(), marker) {
			return output.String()
		}
	}
}
