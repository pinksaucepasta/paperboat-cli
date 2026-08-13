//go:build darwin || linux

package localdaemon

import (
	"context"
	"errors"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/managedssh"
)

func TestManagedSSHRuntimeRejectsIncompleteConfiguration(t *testing.T) {
	if _, err := StartManagedSSH(context.Background(), ManagedSSHConfig{}); !errors.Is(err, ErrInvalidInventoryConfig) {
		t.Fatalf("err=%v", err)
	}
}

func TestManagedSSHHealthCodeIsTyped(t *testing.T) {
	if code := ManagedSSHHealthCode(nil); code != "" {
		t.Fatalf("healthy code=%q", code)
	}
	if code := ManagedSSHHealthCode(managedssh.ErrOpenSSHUnavailable); code != "ssh_target_not_ready" {
		t.Fatalf("OpenSSH code=%q", code)
	}
	if code := ManagedSSHHealthCode(errors.New("registration failed")); code != "ssh_key_rejected" {
		t.Fatalf("registration code=%q", code)
	}
}
