//go:build windows

package updated

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestWindowsActivationMovesAfterLockedBinaryRelease exercises the same
// sharing-violation retry used by the production slot rotation. The fixture is
// entirely under a unique temporary root and never touches the installed
// Paperboat binary or SCM.
func TestWindowsActivationMovesAfterLockedBinaryRelease(t *testing.T) {
	root, err := os.MkdirTemp("", "trk34-update-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	active := filepath.Join(root, "trk34-update-active.exe")
	rollback := filepath.Join(root, "trk34-update-rollback.exe")
	if err := os.WriteFile(active, []byte("active-binary"), 0o700); err != nil {
		t.Fatal(err)
	}

	activePointer, err := windows.UTF16PtrFromString(active)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := windows.CreateFile(activePointer, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = windows.CloseHandle(locked)
		}
	})

	rollbackPointer, err := windows.UTF16PtrFromString(rollback)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.MoveFileEx(activePointer, rollbackPointer, windows.MOVEFILE_WRITE_THROUGH); err == nil {
		t.Fatal("locked active binary was moved before its no-delete-share handle was released")
	} else if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("locked active binary move error=%v, want sharing violation or access denied", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started := time.Now()
	moved := make(chan error, 1)
	go func() { moved <- moveWindowsActivationFile(ctx, active, rollback) }()
	// Keep the lock long enough to force at least one bounded retry, then
	// release it as a running process would after its shutdown handshake.
	timer := time.NewTimer(500 * time.Millisecond)
	<-timer.C
	if err := windows.CloseHandle(locked); err != nil {
		t.Fatal(err)
	}
	closed = true

	select {
	case err := <-moved:
		if err != nil {
			t.Fatalf("move after locked binary release: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("move after locked binary release timed out: %v", ctx.Err())
	}
	if _, err := os.Stat(active); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active slot still exists after move: %v", err)
	}
	body, err := os.ReadFile(rollback)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "active-binary" {
		t.Fatalf("rollback slot contents=%q", body)
	}
	t.Logf("locked binary move retried and completed after release in %s", time.Since(started).Round(time.Millisecond))
}
