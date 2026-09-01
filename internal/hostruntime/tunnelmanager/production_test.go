package tunnelmanager

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
)

func TestOpenProductionOwnsStateLockUntilShutdown(t *testing.T) {
	root := t.TempDir()
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{}, err: map[uint64]error{}}
	config := ProductionConfig{StateRoot: root, HostID: "host_01", Factory: factory, Report: func(Observation) {}}
	manager, status, err := OpenProduction(config)
	if err != nil || status.Degraded {
		t.Fatalf("open production manager: status=%+v err=%v", status, err)
	}
	applier, err := manager.ConfigApplier(nil, testManagedTunnelEndpointID)
	if err != nil || applier.Manager != manager.Manager || applier.State == nil {
		t.Fatalf("production config applier does not share manager/store lifecycle: applier=%+v err=%v", applier, err)
	}
	if _, _, err := OpenProduction(config); !errors.Is(err, hoststate.ErrLocked) {
		t.Fatalf("second manager must not share durable state lock: %v", err)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	reopened, _, err := OpenProduction(config)
	if err != nil {
		t.Fatalf("state lock was not released: %v", err)
	}
	if err := reopened.Shutdown(context.Background()); err != nil {
		t.Fatalf("reopened shutdown: %v", err)
	}
}

func TestProductionConfigApplierRejectsNonCanonicalStableEndpointID(t *testing.T) {
	root := t.TempDir()
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{}, err: map[uint64]error{}}
	manager, _, err := OpenProduction(ProductionConfig{StateRoot: root, HostID: "host_01", Factory: factory, Report: func(Observation) {}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	for _, stableEndpointID := range []string{"", "endpoint_01", "tep_0123456789abcdef"} {
		if _, err := manager.ConfigApplier(nil, stableEndpointID); !errors.Is(err, hoststate.ErrInvalidState) {
			t.Fatalf("stable endpoint ID %q error = %v, want hoststate.ErrInvalidState", stableEndpointID, err)
		}
	}
}

func TestOpenProductionClosesStoreAfterManagerValidationFailure(t *testing.T) {
	root := t.TempDir()
	bad := ProductionConfig{StateRoot: root, HostID: "host_01", Factory: nil, Report: func(Observation) {}}
	if _, _, err := OpenProduction(bad); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected invalid config, got %v", err)
	}
	good := bad
	good.Factory = &fakeFactory{candidates: map[uint64][]*fakeCandidate{}, err: map[uint64]error{}}
	manager, _, err := OpenProduction(good)
	if err != nil {
		t.Fatalf("constructor failure leaked store lock: %v", err)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func TestOpenProductionRejectsBroadOrNonCanonicalStateRoot(t *testing.T) {
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{}, err: map[uint64]error{}}
	for _, root := range []string{"relative", string(filepath.Separator), t.TempDir() + string(filepath.Separator) + ".." + string(filepath.Separator) + "state"} {
		_, _, err := OpenProduction(ProductionConfig{StateRoot: root, HostID: "host_01", Factory: factory, Report: func(Observation) {}})
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("state root %q: expected invalid config, got %v", root, err)
		}
	}
}

func TestProductionShutdownDeadlineRetainsLockUntilBackgroundCloseFinishes(t *testing.T) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, productionStateDirectory)
	seed, _, err := hoststate.Open(hoststate.Config{Root: stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	state := tunnelState(t, 1, 1)
	_, revision, err := seed.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seed.Commit(revision, state); err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	closeStarted := make(chan struct{})
	releaseClose := make(chan struct{})
	active := &fakeActive{closeFn: func(context.Context) error {
		close(closeStarted)
		<-releaseClose
		return nil
	}}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{1: {{probe: ProbeResult{Ready: true}, active: active}}}, err: map[uint64]error{}}
	config := ProductionConfig{StateRoot: root, HostID: "host_01", Factory: factory, Report: func(Observation) {}}
	manager, _, err := OpenProduction(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	firstDone := make(chan error, 1)
	go func() { firstDone <- manager.Shutdown(shutdownCtx) }()
	<-closeStarted
	if err := <-firstDone; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first shutdown = %v", err)
	}
	if _, _, err := OpenProduction(config); !errors.Is(err, hoststate.ErrLocked) {
		t.Fatalf("store lock released before carrier closed: %v", err)
	}
	close(releaseClose)
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	reopened, _, err := OpenProduction(config)
	if err != nil {
		t.Fatalf("store did not reopen after completed shutdown: %v", err)
	}
	if err := reopened.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestProductionShutdownRetriesCarrierCloseBeforeReleasingLock(t *testing.T) {
	root := t.TempDir()
	seed, _, err := hoststate.Open(hoststate.Config{Root: filepath.Join(root, productionStateDirectory)})
	if err != nil {
		t.Fatal(err)
	}
	_, revision, err := seed.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seed.Commit(revision, tunnelState(t, 1, 1)); err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	closeFailure := errors.New("carrier close failed")
	closeAttempts := 0
	active := &fakeActive{closeFn: func(context.Context) error {
		closeAttempts++
		if closeAttempts == 1 {
			return closeFailure
		}
		return nil
	}}
	factory := &fakeFactory{candidates: map[uint64][]*fakeCandidate{1: {{probe: ProbeResult{Ready: true}, active: active}}}, err: map[uint64]error{}}
	config := ProductionConfig{StateRoot: root, HostID: "host_01", Factory: factory, Report: func(Observation) {}}
	manager, _, err := OpenProduction(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Shutdown(context.Background()); !errors.Is(err, closeFailure) {
		t.Fatalf("first shutdown = %v", err)
	}
	if _, _, err := OpenProduction(config); !errors.Is(err, hoststate.ErrLocked) {
		t.Fatalf("failed close released store lock: %v", err)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatalf("retry shutdown = %v", err)
	}
	if closeAttempts != 2 {
		t.Fatalf("close attempts = %d", closeAttempts)
	}
	reopened, _, err := OpenProduction(config)
	if err != nil {
		t.Fatalf("store did not reopen after successful retry: %v", err)
	}
	if err := reopened.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}
