package preview

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type dispatchResolver struct {
	mu      sync.Mutex
	count   int
	carrier Carrier
	err     error
}

func (r *dispatchResolver) ResolvePreviewCarrier(_ context.Context, _ DispatchRequest) (Carrier, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count++
	return r.carrier, r.err
}

type dispatchObserver struct {
	mu       sync.Mutex
	count    int
	expected int64
}

type dispatchOwners struct{ done <-chan struct{} }

func (o dispatchOwners) OwnerSessionDone(accountID, machineID, ownerSessionID string) (<-chan struct{}, error) {
	if accountID == "" || machineID == "" || ownerSessionID == "" || o.done == nil {
		return nil, ErrDispatchInvalid
	}
	return o.done, nil
}

func (o *dispatchObserver) ObservePreviewReadiness(_ context.Context, readiness DispatchReadiness, lease Lease, expected int64) (Lease, error) {
	if readiness.OperationID == "" || readiness.IdempotencyKey == "" || readiness.RequestID == "" || readiness.CorrelationID == "" {
		return Lease{}, ErrDispatchInvalid
	}
	o.mu.Lock()
	o.count++
	o.expected = expected
	o.mu.Unlock()
	lease = sessionReadyLease(lease)
	lease.ETag = formatLeaseETag(lease.ID, expected+1)
	lease.Generation = expected + 1
	return lease, nil
}

func testDispatchRequest(t *testing.T, now time.Time) DispatchRequest {
	t.Helper()
	request := DispatchRequest{
		Schema: PreviewTunnelSchemaV1, Kind: PreviewDispatchKind,
		PreviewID: "prv_dispatch_1", OperationID: "operation_dispatch_1", AccountID: "account_1", ActorID: "actor_1",
		OwnerDeviceID: "machine_1", OwnerSessionID: "session_dispatch_1",
		Target: LeaseTarget{Scheme: "http", Address: "127.0.0.1:3000"}, AccessMode: "public",
		Endpoint: "https://dispatch.preview.example.test", LeaseDeadline: now.Add(time.Hour),
		LeaseETag: formatLeaseETag("prv_dispatch_1", 1), ExpectedGeneration: 1,
		IdempotencyKey: "preview_dispatch_key_1", RequestID: "request_dispatch_1", CorrelationID: "correlation_dispatch_1",
		State: "allocating", AllocationState: "pending", EdgeState: "pending", OriginState: "unknown",
		CreatedAt: now, LastRenewedAt: now,
	}
	hash, err := request.ComputeRequestHash()
	if err != nil {
		t.Fatal(err)
	}
	request.RequestHash = hash
	return request
}

func testDispatchAuthorization(request DispatchRequest, now time.Time) DispatchAuthorization {
	return DispatchAuthorization{
		AccountID: request.AccountID, ActorID: request.ActorID, MachineID: request.OwnerDeviceID,
		OwnerSessionID: request.OwnerSessionID, PreviewID: request.PreviewID, OperationID: request.OperationID,
		ExpectedGeneration: request.ExpectedGeneration, RequestHash: request.RequestHash, ExpiresAt: now.Add(time.Minute),
		IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID, CorrelationID: request.CorrelationID,
	}
}

func TestDispatchStartsExistingLeaseOnceAndReportsObservedReadiness(t *testing.T) {
	now := time.Date(2098, 1, 2, 3, 4, 5, 0, time.UTC)
	started := make(chan struct{})
	carrier := &sessionCarrier{closed: make(chan struct{}), run: func(ctx context.Context, lease Lease, ready func(Lease) error) error {
		close(started)
		if err := ready(sessionReadyLease(lease)); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}}
	resolver := &dispatchResolver{carrier: carrier}
	observer := &dispatchObserver{}
	leases := &sessionLeaseClient{}
	ownerDone := make(chan struct{})
	manager, err := NewDispatchManager(DispatchManagerConfig{MachineID: "machine_1", Leases: leases, Carriers: resolver, Readiness: observer, Owners: dispatchOwners{done: ownerDone}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := manager.Shutdown(shutdownCtx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	})

	request := testDispatchRequest(t, now)
	authorization := testDispatchAuthorization(request, now)
	accepted, err := manager.Dispatch(context.Background(), authorization, request)
	if err != nil || accepted.State != "accepted" || accepted.Generation != 1 {
		t.Fatalf("accepted=%+v err=%v", accepted, err)
	}
	<-started
	deadline := time.Now().Add(time.Second)
	for {
		replayed, replayErr := manager.Dispatch(context.Background(), authorization, request)
		if replayErr != nil {
			t.Fatal(replayErr)
		}
		if replayed.State == "ready" {
			if replayed.Generation != 2 {
				t.Fatalf("ready generation=%d", replayed.Generation)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("dispatch did not become ready")
		}
		time.Sleep(time.Millisecond)
	}
	resolver.mu.Lock()
	resolveCount := resolver.count
	resolver.mu.Unlock()
	observer.mu.Lock()
	observeCount, expected := observer.count, observer.expected
	observer.mu.Unlock()
	leases.mu.Lock()
	createdCount := len(leases.created)
	leases.mu.Unlock()
	if resolveCount != 1 || observeCount != 1 || expected != 1 || createdCount != 0 || manager.config.Sessions.Count() != 1 {
		t.Fatalf("resolve=%d observe=%d expected=%d create=%d sessions=%d", resolveCount, observeCount, expected, createdCount, manager.config.Sessions.Count())
	}
}

func TestDispatchReadinessUsesCurrentGenerationAfterRenewal(t *testing.T) {
	now := time.Date(2098, 1, 2, 3, 4, 5, 0, time.UTC)
	started := make(chan Lease, 1)
	release := make(chan struct{})
	carrier := &sessionCarrier{run: func(ctx context.Context, lease Lease, ready func(Lease) error) error {
		started <- lease
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		if err := ready(sessionReadyLease(lease)); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}}
	observer := &dispatchObserver{}
	manager, err := NewDispatchManager(DispatchManagerConfig{
		MachineID: "machine_1", Leases: &sessionLeaseClient{}, Carriers: &dispatchResolver{carrier: carrier},
		Readiness: observer, Owners: dispatchOwners{done: make(chan struct{})}, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Shutdown(context.Background()) })
	request := testDispatchRequest(t, now)
	if _, err := manager.Dispatch(context.Background(), testDispatchAuthorization(request, now), request); err != nil {
		t.Fatal(err)
	}
	<-started
	manager.mu.Lock()
	session := manager.operations[request.OperationID].session
	manager.mu.Unlock()
	if session == nil {
		t.Fatal("dispatch session is unavailable")
	}
	previous := session.currentLease()
	renewed := previous
	renewed.Generation = 2
	renewed.ETag = formatLeaseETag(renewed.ID, 2)
	renewed.LastRenewedAt = now.Add(time.Minute)
	if err := session.acceptRenewal(renewed, previous); err != nil {
		t.Fatalf("advance lease before readiness: %v", err)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for {
		observer.mu.Lock()
		count, expected := observer.count, observer.expected
		observer.mu.Unlock()
		if count == 1 {
			if expected != 2 {
				t.Fatalf("readiness CAS generation=%d, want 2", expected)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("readiness was not observed")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDispatchRejectsWrongMachineHashAndMismatchedReplay(t *testing.T) {
	now := time.Date(2098, 1, 2, 3, 4, 5, 0, time.UTC)
	carrier := &sessionCarrier{run: func(ctx context.Context, _ Lease, _ func(Lease) error) error { <-ctx.Done(); return ctx.Err() }}
	resolver := &dispatchResolver{carrier: carrier}
	manager, err := NewDispatchManager(DispatchManagerConfig{MachineID: "machine_1", Leases: &sessionLeaseClient{}, Carriers: resolver, Readiness: &dispatchObserver{}, Owners: dispatchOwners{done: make(chan struct{})}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Shutdown(context.Background()) })

	wrongMachine := testDispatchRequest(t, now)
	wrongMachine.OwnerDeviceID = "machine_2"
	wrongMachine.RequestHash, err = wrongMachine.ComputeRequestHash()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Dispatch(context.Background(), testDispatchAuthorization(wrongMachine, now), wrongMachine); !errors.Is(err, ErrDispatchInvalid) {
		t.Fatalf("wrong machine err=%v", err)
	}

	request := testDispatchRequest(t, now)
	authorization := testDispatchAuthorization(request, now)
	if _, err := manager.Dispatch(context.Background(), authorization, request); err != nil {
		t.Fatal(err)
	}
	mismatch := request
	mismatch.Target.Address = "127.0.0.1:4000"
	mismatch.RequestHash, err = mismatch.ComputeRequestHash()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Dispatch(context.Background(), testDispatchAuthorization(mismatch, now), mismatch); !errors.Is(err, ErrDispatchConflict) {
		t.Fatalf("mismatched replay err=%v", err)
	}
}

func TestDispatchCarrierFailureDoesNotReserveOperation(t *testing.T) {
	now := time.Date(2098, 1, 2, 3, 4, 5, 0, time.UTC)
	resolver := &dispatchResolver{err: errors.New("edge unavailable")}
	manager, err := NewDispatchManager(DispatchManagerConfig{MachineID: "machine_1", Leases: &sessionLeaseClient{}, Carriers: resolver, Readiness: &dispatchObserver{}, Owners: dispatchOwners{done: make(chan struct{})}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	request := testDispatchRequest(t, now)
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := manager.Dispatch(context.Background(), testDispatchAuthorization(request, now), request); !errors.Is(err, ErrDispatchUnavailable) {
			t.Fatalf("attempt %d err=%v", attempt, err)
		}
	}
	resolver.mu.Lock()
	count := resolver.count
	resolver.mu.Unlock()
	if count != 2 {
		t.Fatalf("resolve attempts=%d", count)
	}
}

func TestDispatchRejectsAuthorizationMismatchAndPendingReadiness(t *testing.T) {
	now := time.Date(2098, 1, 2, 3, 4, 5, 0, time.UTC)
	pendingAttempted := make(chan struct{})
	carrier := &sessionCarrier{run: func(_ context.Context, lease Lease, ready func(Lease) error) error {
		defer close(pendingAttempted)
		return ready(lease)
	}}
	manager, err := NewDispatchManager(DispatchManagerConfig{
		MachineID: "machine_1", Leases: &sessionLeaseClient{}, Carriers: &dispatchResolver{carrier: carrier},
		Readiness: &dispatchObserver{}, Owners: dispatchOwners{done: make(chan struct{})}, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Shutdown(context.Background()) })
	request := testDispatchRequest(t, now)
	authorization := testDispatchAuthorization(request, now)
	authorization.AccountID = "account_other"
	if _, err := manager.Dispatch(context.Background(), authorization, request); !errors.Is(err, ErrDispatchInvalid) {
		t.Fatalf("authorization mismatch err=%v", err)
	}
	authorization = testDispatchAuthorization(request, now)
	if _, err := manager.Dispatch(context.Background(), authorization, request); err != nil {
		t.Fatal(err)
	}
	<-pendingAttempted
	deadline := time.Now().Add(time.Second)
	for {
		outcome, replayErr := manager.Dispatch(context.Background(), authorization, request)
		if replayErr != nil {
			t.Fatal(replayErr)
		}
		if outcome.State == "failed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending carrier was promoted: %+v", outcome)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDispatchOwnerLossStopsAndUntracksSession(t *testing.T) {
	now := time.Date(2098, 1, 2, 3, 4, 5, 0, time.UTC)
	ownerDone := make(chan struct{})
	stopDone := make(chan struct{})
	leases := &sessionLeaseClient{stopDone: stopDone}
	carrier := &sessionCarrier{run: func(ctx context.Context, lease Lease, ready func(Lease) error) error {
		if err := ready(sessionReadyLease(lease)); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}}
	observer := &dispatchObserver{}
	manager, err := NewDispatchManager(DispatchManagerConfig{
		MachineID: "machine_1", Leases: leases, Carriers: &dispatchResolver{carrier: carrier}, Readiness: observer,
		Owners: dispatchOwners{done: ownerDone}, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Shutdown(context.Background()) })
	request := testDispatchRequest(t, now)
	if _, err := manager.Dispatch(context.Background(), testDispatchAuthorization(request, now), request); err != nil {
		t.Fatal(err)
	}
	close(ownerDone)
	select {
	case <-stopDone:
	case <-time.After(time.Second):
		t.Fatal("owner loss did not stop lease")
	}
	deadline := time.Now().Add(time.Second)
	for manager.config.Sessions.Count() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("sessions after owner loss=%d", manager.config.Sessions.Count())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestReadyLeaseAdvancesRenewalAndManagerGeneration(t *testing.T) {
	now := time.Now().UTC()
	request := LeaseRequest{OwnerDeviceID: "machine_1", OwnerSessionID: "session_ready_generation", Target: LeaseTarget{Scheme: "http", Address: "127.0.0.1:3000"}, AccessMode: "public"}
	lease := sessionTestLease(request)
	lease.ID = "prv_ready_generation"
	lease.ETag = formatLeaseETag(lease.ID, 1)
	carrier := &sessionCarrier{run: func(ctx context.Context, current Lease, ready func(Lease) error) error {
		observed := sessionReadyLease(current)
		observed.ETag = formatLeaseETag(current.ID, 2)
		if err := ready(observed); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}}
	session, err := StartExisting(context.Background(), SessionConfig{
		LeaseClient: &sessionLeaseClient{}, Carrier: carrier, OwnerDeviceID: request.OwnerDeviceID,
		OwnerSessionID: request.OwnerSessionID, Target: request.Target, AccessMode: request.AccessMode,
		DisableParentWatch: true, RenewInterval: time.Hour, Now: func() time.Time { return now },
	}, lease)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewSessionManager()
	if err := manager.Track(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Shutdown(context.Background()) })
	ready, err := session.WaitReady(context.Background())
	if err != nil || ready.Generation != 2 || session.currentLease().Generation != 2 {
		t.Fatalf("ready=%+v current=%+v err=%v", ready, session.currentLease(), err)
	}
	if _, err := manager.Get(SessionKey{LeaseID: lease.ID, OwnerSessionID: lease.OwnerSessionID, Generation: 1}); !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("old generation remained tracked: %v", err)
	}
	if tracked, err := manager.Get(SessionKey{LeaseID: lease.ID, OwnerSessionID: lease.OwnerSessionID, Generation: 2}); err != nil || tracked != session {
		t.Fatalf("ready generation not tracked: session=%p err=%v", tracked, err)
	}
}
