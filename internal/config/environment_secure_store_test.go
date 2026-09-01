package config

import (
	"errors"
	"testing"
	"time"

	"github.com/adrg/xdg"
)

func TestLockEnvironmentHostKeySerializesPerInstallation(t *testing.T) {
	previousConfigHome := xdg.ConfigHome
	configHome := t.TempDir()
	xdg.ConfigHome = configHome
	t.Cleanup(func() { xdg.ConfigHome = previousConfigHome })

	first, err := (KeyringStore{}).LockEnvironmentHostKey("machine_1", 4)
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan error, 1)
	go func() {
		second, err := (KeyringStore{}).LockEnvironmentHostKey("machine_1", 4)
		if err == nil {
			err = second()
		}
		acquired <- err
	}()
	select {
	case err := <-acquired:
		t.Fatalf("second host-key transaction acquired before first released: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	if err := first(); err != nil {
		t.Fatal(err)
	}
	if err := <-acquired; err != nil {
		t.Fatal(err)
	}

	if _, err := (KeyringStore{}).LockEnvironmentHostKey("machine_1", 0); !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("invalid generation error=%v", err)
	}
}
