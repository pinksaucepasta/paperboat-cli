package preview

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestLeaseObserverCarrierWaitsForStableHostReadiness(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	base := Lease{
		Schema: PreviewTunnelSchemaV1, Kind: PreviewLeaseKind, ID: "preview_observer_01", AccountID: "account_01", ActorID: "actor_01",
		OwnerDeviceID: "host_01", OwnerSessionID: "owner_session_01", Target: LeaseTarget{Scheme: "http", Address: "127.0.0.1:8080"}, AccessMode: "public",
		Endpoint: "https://preview.example.test", LeaseDeadline: now.Add(time.Hour), State: "connecting", AllocationState: "pending", EdgeState: "pending", OriginState: "unknown",
		CreatedAt: now.Add(-time.Minute), LastRenewedAt: now, CreateOperationID: "operation_observer_01", ETag: formatLeaseETag("preview_observer_01", 1), Generation: 1,
	}
	readyLease := base
	readyLease.State, readyLease.AllocationState, readyLease.EdgeState, readyLease.OriginState = "ready", "ready", "ready", "ready"
	readyLease.ETag = formatLeaseETag(base.ID, 2)
	readyLease.Generation = 2

	var mu sync.Mutex
	reads := 0
	carrier, err := NewLeaseObserverCarrier(LeaseObserverCarrierConfig{PollInterval: time.Millisecond, Reader: leaseReaderFunc(func(context.Context, string) (Lease, error) {
		mu.Lock()
		defer mu.Unlock()
		reads++
		if reads == 1 {
			return base, nil
		}
		return readyLease, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan Lease, 1)
	done := make(chan error, 1)
	go func() { done <- carrier.Run(ctx, base, func(lease Lease) error { ready <- lease; return nil }) }()
	select {
	case observed := <-ready:
		if observed.ID != base.ID || observed.Generation != 2 || !isReadyLease(observed) || observed.CreateOperationID != base.CreateOperationID {
			t.Fatalf("observed lease = %+v", observed)
		}
	case <-time.After(time.Second):
		t.Fatal("observer did not report host readiness")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("observer run = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("observer did not stop after context cancellation")
	}
}

func TestLeaseObserverCarrierRejectsChangedLease(t *testing.T) {
	now := time.Now().UTC()
	base := Lease{Schema: PreviewTunnelSchemaV1, Kind: PreviewLeaseKind, ID: "preview_observer_02", AccountID: "account_01", ActorID: "actor_01", OwnerDeviceID: "host_01", OwnerSessionID: "owner_session_01", Target: LeaseTarget{Scheme: "http", Address: "127.0.0.1:8080"}, AccessMode: "public", Endpoint: "https://preview.example.test", LeaseDeadline: now.Add(time.Hour), State: "connecting", AllocationState: "pending", EdgeState: "pending", OriginState: "unknown", CreatedAt: now.Add(-time.Minute), LastRenewedAt: now, CreateOperationID: "operation_observer_02", ETag: formatLeaseETag("preview_observer_02", 1), Generation: 1}
	changed := base
	changed.ID = "preview_other_02"
	carrier, err := NewLeaseObserverCarrier(LeaseObserverCarrierConfig{Reader: leaseReaderFunc(func(context.Context, string) (Lease, error) { return changed, nil })})
	if err != nil {
		t.Fatal(err)
	}
	err = carrier.Run(context.Background(), base, func(Lease) error { return nil })
	if !errors.Is(err, ErrLeaseObserverBinding) {
		t.Fatalf("changed lease error = %v", err)
	}
}

func TestLeaseObserverCarrierRequiresReaderAndClosesIdempotently(t *testing.T) {
	carrier, err := NewLeaseObserverCarrier(LeaseObserverCarrierConfig{})
	if err != nil {
		t.Fatal(err)
	}
	base := Lease{ID: "preview_observer_03"}
	if err := carrier.Run(context.Background(), base, func(Lease) error { return nil }); !errors.Is(err, ErrLeaseObserverReaderRequired) {
		t.Fatalf("missing reader error = %v", err)
	}
	if err := carrier.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := carrier.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := carrier.SetLeaseReader(leaseReaderFunc(func(context.Context, string) (Lease, error) { return base, nil })); !errors.Is(err, ErrLeaseObserverClosed) {
		t.Fatalf("reader after close error = %v", err)
	}
}

type leaseReaderFunc func(context.Context, string) (Lease, error)

func (f leaseReaderFunc) Get(ctx context.Context, id string) (Lease, error) {
	return f(ctx, id)
}
