//go:build windows

package runtime

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
)

type recordingWindowsAuthorizedKeysClient struct {
	keys     []string
	deadline bool
	changed  bool
	err      error
}

func (c *recordingWindowsAuthorizedKeysClient) ReconcileAuthorizedKeys(ctx context.Context, keys []string) (bool, error) {
	_, c.deadline = ctx.Deadline()
	c.keys = make([]string, len(keys))
	copy(c.keys, keys)
	return c.changed, c.err
}

func TestWindowsManagedSSHDelegatesAuthorizedKeysToPrivilegedHostService(t *testing.T) {
	previous := newWindowsAuthorizedKeysClient
	t.Cleanup(func() { newWindowsAuthorizedKeysClient = previous })
	recorder := &recordingWindowsAuthorizedKeysClient{changed: true}
	newWindowsAuthorizedKeysClient = func(timeout time.Duration) (windowsAuthorizedKeysClient, error) {
		if timeout != 5*time.Second {
			t.Fatalf("timeout=%s", timeout)
		}
		return recorder, nil
	}
	keys := []string{"ssh-ed25519 test"}
	root := filepath.Join(hostinstall.WindowsProgramDataRoot(), "ssh")
	changed, err := reconcilePlatformAuthorizedKeys(root, 0, keys)
	if err != nil || !changed || !recorder.deadline || !reflect.DeepEqual(recorder.keys, keys) {
		t.Fatalf("changed=%t deadline=%t keys=%v err=%v", changed, recorder.deadline, recorder.keys, err)
	}
	if _, err := reconcilePlatformAuthorizedKeys(`C:\Users\Pujan\.ssh`, 0, keys); err == nil {
		t.Fatal("owner-selected authorized-keys root was accepted")
	}
}
