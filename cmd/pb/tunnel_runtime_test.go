package main

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestEnsureTunnelHostRuntimeRepairsOnceThenRequiresReadiness(t *testing.T) {
	oldProbe, oldRepair := tunnelHostRuntimeProbe, tunnelHostRuntimeRepair
	t.Cleanup(func() { tunnelHostRuntimeProbe, tunnelHostRuntimeRepair = oldProbe, oldRepair })
	var probes, repairs atomic.Int32
	tunnelHostRuntimeProbe = func(context.Context, string) error {
		if probes.Add(1) >= 2 {
			return nil
		}
		return errors.New("stopped")
	}
	tunnelHostRuntimeRepair = func(context.Context) error {
		repairs.Add(1)
		return nil
	}
	if err := ensureTunnelHostRuntime(t.Context(), filepath.Join(t.TempDir(), "state")); err != nil {
		t.Fatal(err)
	}
	if probes.Load() != 2 || repairs.Load() != 1 {
		t.Fatalf("probes=%d repairs=%d", probes.Load(), repairs.Load())
	}
}

func TestEnsureTunnelHostRuntimeDoesNotElevateWhenReady(t *testing.T) {
	oldProbe, oldRepair := tunnelHostRuntimeProbe, tunnelHostRuntimeRepair
	t.Cleanup(func() { tunnelHostRuntimeProbe, tunnelHostRuntimeRepair = oldProbe, oldRepair })
	var repairs atomic.Int32
	tunnelHostRuntimeProbe = func(context.Context, string) error { return nil }
	tunnelHostRuntimeRepair = func(context.Context) error {
		repairs.Add(1)
		return errors.New("must not run")
	}
	if err := ensureTunnelHostRuntime(t.Context(), filepath.Join(t.TempDir(), "state")); err != nil {
		t.Fatal(err)
	}
	if repairs.Load() != 0 {
		t.Fatal("healthy host triggered repair")
	}
}

func TestEnsureTunnelHostRuntimeFailsClosedOnRepairError(t *testing.T) {
	oldProbe, oldRepair := tunnelHostRuntimeProbe, tunnelHostRuntimeRepair
	t.Cleanup(func() { tunnelHostRuntimeProbe, tunnelHostRuntimeRepair = oldProbe, oldRepair })
	want := errors.New("repair denied")
	tunnelHostRuntimeProbe = func(context.Context, string) error { return errors.New("stopped") }
	tunnelHostRuntimeRepair = func(context.Context) error { return want }
	if err := ensureTunnelHostRuntime(t.Context(), filepath.Join(t.TempDir(), "state")); !errors.Is(err, want) {
		t.Fatalf("error=%v", err)
	}
}
