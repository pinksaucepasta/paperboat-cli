package hostinstall

import (
	"context"
	"errors"
	"testing"
)

func TestActivateExistingLocalDaemonStartsWithoutReinstall(t *testing.T) {
	started, installed, ready := 0, 0, 0
	err := activateLocalDaemon(context.Background(), localDaemonActivation{
		Installed: true,
		Start: func(context.Context) error {
			started++
			return nil
		},
		Install: func(context.Context) error {
			installed++
			return nil
		},
		WaitReady: func(context.Context) error {
			ready++
			return nil
		},
	})
	if err != nil || started != 1 || installed != 0 || ready != 1 {
		t.Fatalf("error=%v started=%d installed=%d ready=%d", err, started, installed, ready)
	}
}

func TestActivateMissingLocalDaemonInstallsOnce(t *testing.T) {
	started, installed, ready := 0, 0, 0
	err := activateLocalDaemon(context.Background(), localDaemonActivation{
		Start: func(context.Context) error {
			started++
			return nil
		},
		Install: func(context.Context) error {
			installed++
			return nil
		},
		WaitReady: func(context.Context) error {
			ready++
			return nil
		},
	})
	if err != nil || started != 0 || installed != 1 || ready != 1 {
		t.Fatalf("error=%v started=%d installed=%d ready=%d", err, started, installed, ready)
	}
}

func TestActivateLocalDaemonDoesNotReportReadinessAfterStartFailure(t *testing.T) {
	want := errors.New("start failed")
	ready := false
	err := activateLocalDaemon(context.Background(), localDaemonActivation{
		Installed: true,
		Start:     func(context.Context) error { return want },
		Install:   func(context.Context) error { return nil },
		WaitReady: func(context.Context) error {
			ready = true
			return nil
		},
	})
	if !errors.Is(err, want) || ready {
		t.Fatalf("error=%v ready=%t", err, ready)
	}
}
