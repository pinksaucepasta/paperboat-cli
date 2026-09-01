package connectorprotocol

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

type stagedConfig struct {
	owner     *stagedApplier
	activated bool
	aborted   bool
}

func (s *stagedConfig) Activate(ctx context.Context) error {
	s.owner.mu.Lock()
	activateErr := s.owner.activateErr
	activateStarted := s.owner.activateStarted
	activateRelease := s.owner.activateRelease
	s.owner.mu.Unlock()
	if activateStarted != nil {
		s.owner.activateStartedOnce.Do(func() { close(activateStarted) })
	}
	if activateRelease != nil {
		select {
		case <-activateRelease:
		case <-ctx.Done():
		}
	}
	s.owner.mu.Lock()
	if activateErr != nil {
		s.owner.mu.Unlock()
		return activateErr
	}
	s.activated = true
	s.owner.mu.Unlock()
	if s.owner.events != nil {
		s.owner.events <- "activation_done"
	}
	return nil
}

func (s *stagedConfig) Abort(context.Context) error {
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	s.aborted = true
	return s.owner.abortErr
}

type stagedApplier struct {
	mu                  sync.Mutex
	prepareErr          error
	activateErr         error
	abortErr            error
	prepared            []*stagedConfig
	activateStarted     chan struct{}
	activateRelease     chan struct{}
	activateStartedOnce sync.Once
	events              chan string
}

type testDrainer struct {
	mu         sync.Mutex
	active     uint32
	stopCalls  int
	forceCalls int
	stopErr    error
	activeErr  error
	forceErr   error
}

func (d *testDrainer) StopNewStreams(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopCalls++
	return d.stopErr
}

func (d *testDrainer) ActiveStreams(context.Context) (uint32, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.active, d.activeErr
}

func (d *testDrainer) ForceClose(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.forceCalls++
	if d.forceErr == nil {
		d.active = 0
	}
	return d.forceErr
}

func (a *stagedApplier) PrepareSnapshot(context.Context, Snapshot) (PreparedConfig, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.prepareErr != nil {
		return nil, a.prepareErr
	}
	prepared := &stagedConfig{owner: a}
	a.prepared = append(a.prepared, prepared)
	return prepared, nil
}

func (a *stagedApplier) PrepareDelta(ctx context.Context, delta Delta) (PreparedConfig, error) {
	return a.PrepareSnapshot(ctx, Snapshot{Generation: delta.Generation})
}

func testSessionPair(t *testing.T) (*ServerSession, *ClientSession, *testClock, *stagedApplier, Snapshot) {
	t.Helper()
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	auth, private := testAuth(t, now, 1)
	snapshot, err := NewSnapshot("tunnel_1", 1, testConfigPayload(1, "preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerConfig{
		Authenticator: AuthenticatorFuncs{AuthenticateFunc: func(context.Context, AuthRequest) (AuthResult, error) {
			return AuthResult{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, IdentityKeyID: auth.IdentityKeyID, IdentityKeyThumbprint: auth.IdentityKeyThumbprint, ProcessGeneration: auth.ProcessGeneration, CredentialGeneration: auth.CredentialGeneration, CredentialExpiresAt: now.Add(time.Hour), LeaseExpiresAt: now.Add(time.Hour)}, nil
		}, RenewFunc: func(context.Context, RenewalRequest) (AuthResult, error) {
			return AuthResult{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, IdentityKeyID: auth.IdentityKeyID, IdentityKeyThumbprint: auth.IdentityKeyThumbprint, ProcessGeneration: auth.ProcessGeneration, CredentialGeneration: auth.CredentialGeneration + 1, CredentialExpiresAt: clock.Now().Add(time.Hour), LeaseExpiresAt: clock.Now().Add(time.Hour)}, nil
		}},
		Snapshots:    SnapshotSourceFunc(func(context.Context, string) (Snapshot, error) { return snapshot, nil }),
		Capabilities: requiredCapabilityList(), Clock: clock, LeaseDuration: time.Minute, HeartbeatInterval: 10 * time.Second,
		SessionIDs: func() (string, error) { return "sess_1", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	serverSession, welcome, first, err := server.Accept(context.Background(), Hello{Protocol: ProtocolName, MinVersion: "1.0", MaxVersion: "1.0", AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, ProcessGeneration: auth.ProcessGeneration, Capabilities: requiredCapabilityList(), Auth: auth})
	if err != nil {
		t.Fatal(err)
	}
	if first.ContentHash != snapshot.ContentHash || welcome.Lease.SessionID != welcome.SessionID {
		t.Fatal("server did not return the bound first snapshot")
	}
	applier := &stagedApplier{}
	client, err := NewClientSession(ClientSessionConfig{Hello: Hello{Protocol: ProtocolName, MinVersion: "1.0", MaxVersion: "1.0", AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, ProcessGeneration: auth.ProcessGeneration, Capabilities: requiredCapabilityList(), Auth: auth}, Applier: applier, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AcceptWelcome(welcome); err != nil {
		t.Fatal(err)
	}
	ack, err := client.ApplySnapshot(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverSession.HandleAck(context.Background(), ack); err != nil {
		t.Fatal(err)
	}
	readiness, err := client.MarkReady(true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serverSession.HandleReadiness(context.Background(), readiness); err != nil {
		t.Fatal(err)
	}
	if _, ready, _ := serverSession.Current(); !ready {
		t.Fatal("initial session is not ready")
	}
	_ = private
	return serverSession, client, clock, applier, snapshot
}

func testPendingSessionPair(t *testing.T) (*ServerSession, *ClientSession, *testClock, Snapshot) {
	t.Helper()
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	auth, _ := testAuth(t, now, 1)
	snapshot, err := NewSnapshot("tunnel_1", 1, testConfigPayload(1, "preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerConfig{
		Authenticator: AuthenticatorFuncs{AuthenticateFunc: func(context.Context, AuthRequest) (AuthResult, error) {
			return AuthResult{AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, IdentityKeyID: auth.IdentityKeyID, IdentityKeyThumbprint: auth.IdentityKeyThumbprint, ProcessGeneration: auth.ProcessGeneration, CredentialGeneration: auth.CredentialGeneration, CredentialExpiresAt: now.Add(time.Hour), LeaseExpiresAt: now.Add(time.Hour)}, nil
		}},
		Snapshots:    SnapshotSourceFunc(func(context.Context, string) (Snapshot, error) { return snapshot, nil }),
		Capabilities: requiredCapabilityList(), Clock: clock, LeaseDuration: time.Minute, HeartbeatInterval: 10 * time.Second,
		SessionIDs: func() (string, error) { return "sess_pending", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	serverSession, welcome, first, err := server.Accept(context.Background(), Hello{Protocol: ProtocolName, MinVersion: "1.0", MaxVersion: "1.0", AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, ProcessGeneration: auth.ProcessGeneration, Capabilities: requiredCapabilityList(), Auth: auth})
	if err != nil {
		t.Fatal(err)
	}
	applier := &stagedApplier{}
	client, err := NewClientSession(ClientSessionConfig{Hello: Hello{Protocol: ProtocolName, MinVersion: "1.0", MaxVersion: "1.0", AccountID: auth.AccountID, TunnelID: auth.TunnelID, ConnectorID: auth.ConnectorID, HostID: auth.HostID, ProcessGeneration: auth.ProcessGeneration, Capabilities: requiredCapabilityList(), Auth: auth}, Applier: applier, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AcceptWelcome(welcome); err != nil {
		t.Fatal(err)
	}
	ack, err := client.ApplySnapshot(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverSession.HandleAck(context.Background(), ack); err != nil {
		t.Fatal(err)
	}
	if serverSession.State() != SessionAwaitingReady || client.State() != SessionAwaitingReady {
		t.Fatalf("pending states server=%s client=%s", serverSession.State(), client.State())
	}
	return serverSession, client, clock, snapshot
}

func TestClientSessionApplyRenewalIsMonotonicAndReplaySafe(t *testing.T) {
	_, client, clock, _, _ := testSessionPair(t)
	now := clock.Now()
	current := client.Auth()
	result := AuthResult{
		AccountID: current.AccountID, TunnelID: current.TunnelID, ConnectorID: current.ConnectorID,
		SessionID: client.welcome.SessionID, HostID: current.HostID, IdentityKeyID: current.IdentityKeyID,
		IdentityKeyThumbprint: current.IdentityKeyThumbprint, ProcessGeneration: client.Hello().ProcessGeneration,
		CredentialGeneration: current.CredentialGeneration + 1, CredentialExpiresAt: now.Add(2 * time.Minute),
		LeaseExpiresAt: now.Add(90 * time.Second),
	}
	if err := client.ApplyRenewal(result); err != nil {
		t.Fatalf("initial renewal: %v", err)
	}
	acceptedAuth := client.Auth()
	acceptedLease := client.lease.ExpiresAt
	acceptedHeartbeat := client.lastHeartbeatAck

	clock.Advance(time.Second)
	if err := client.ApplyRenewal(result); err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	if replay := client.Auth(); replay != acceptedAuth || !client.lease.ExpiresAt.Equal(acceptedLease) || !client.lastHeartbeatAck.Equal(acceptedHeartbeat) {
		t.Fatalf("exact replay mutated state: auth=%+v lease=%s heartbeat=%s", replay, client.lease.ExpiresAt, client.lastHeartbeatAck)
	}

	extended := result
	extended.CredentialExpiresAt = now.Add(3 * time.Minute)
	extended.LeaseExpiresAt = now.Add(2 * time.Minute)
	if err := client.ApplyRenewal(extended); err != nil {
		t.Fatalf("same-generation extension: %v", err)
	}
	higher := extended
	higher.CredentialGeneration++
	higher.CredentialExpiresAt = now.Add(4 * time.Minute)
	higher.LeaseExpiresAt = now.Add(3 * time.Minute)
	if err := client.ApplyRenewal(higher); err != nil {
		t.Fatalf("higher-generation extension: %v", err)
	}
	monotonicAuth := client.Auth()
	monotonicLease := client.lease.ExpiresAt

	for _, test := range []struct {
		name string
		edit func(*AuthResult)
	}{
		{name: "credential expiry", edit: func(value *AuthResult) { value.CredentialExpiresAt = now.Add(210 * time.Second) }},
		{name: "lease expiry", edit: func(value *AuthResult) { value.LeaseExpiresAt = now.Add(150 * time.Second) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			regressed := higher
			test.edit(&regressed)
			if err := client.ApplyRenewal(regressed); !errors.Is(err, ErrSessionConflict) {
				t.Fatalf("expiry regression error=%v", err)
			}
			if auth := client.Auth(); auth != monotonicAuth || !client.lease.ExpiresAt.Equal(monotonicLease) {
				t.Fatalf("expiry regression mutated state: auth=%+v lease=%s", auth, client.lease.ExpiresAt)
			}
		})
	}
}

func TestSessionPreservesLKGUntilCandidateReadiness(t *testing.T) {
	serverSession, client, _, applier, first := testSessionPair(t)
	second, err := NewSnapshot("tunnel_1", 2, testConfigPayload(2, "next.preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	second.AccountID, second.ConnectorID, second.SessionID, second.ProcessGeneration = "acct_1", "connector_1", "sess_1", 1
	if err := serverSession.OfferSnapshot(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	ack, err := client.ApplySnapshot(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverSession.HandleAck(context.Background(), ack); err != nil {
		t.Fatal(err)
	}
	current, ready, generation := serverSession.Current()
	if !ready || generation != first.Generation || current.ContentHash != first.ContentHash {
		t.Fatalf("LKG lost during candidate apply: generation=%d ready=%t hash=%s", generation, ready, current.ContentHash)
	}
	if len(applier.prepared) != 2 {
		t.Fatalf("prepared configurations=%d", len(applier.prepared))
	}
	applier.activateErr = errors.New("route failed")
	if _, err := client.MarkReady(true, true, true); err == nil {
		t.Fatal("failed activation accepted")
	}
	current, ready, generation = serverSession.Current()
	if !ready || generation != first.Generation || current.ContentHash != first.ContentHash {
		t.Fatal("old ready generation was not preserved after candidate failure")
	}
	if !applier.prepared[1].aborted {
		t.Fatal("failed candidate was not aborted")
	}
}

func TestSessionPromotesCandidateOnlyAfterReadiness(t *testing.T) {
	serverSession, client, _, applier, _ := testSessionPair(t)
	second, _ := NewSnapshot("tunnel_1", 2, testConfigPayload(2, "next.preview.example.test"))
	second.AccountID, second.ConnectorID, second.SessionID, second.ProcessGeneration = "acct_1", "connector_1", "sess_1", 1
	if err := serverSession.OfferSnapshot(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	ack, err := client.ApplySnapshot(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverSession.HandleAck(context.Background(), ack); err != nil {
		t.Fatal(err)
	}
	if _, err := client.MarkReady(false, true, true); err == nil {
		t.Fatal("not-ready candidate promoted")
	}
	if _, ready, generation := serverSession.Current(); !ready || generation != 1 {
		t.Fatal("LKG became ineligible while candidate was merely not ready")
	}
	readiness, err := client.MarkReady(true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serverSession.HandleReadiness(context.Background(), readiness); err != nil {
		t.Fatal(err)
	}
	current, ready, generation := serverSession.Current()
	if !ready || generation != 2 || current.ContentHash != second.ContentHash || !applier.prepared[1].activated {
		t.Fatalf("candidate not promoted: current=%+v ready=%t generation=%d", current, ready, generation)
	}
}

func TestStaleProcessCannotCloseNewSession(t *testing.T) {
	old, _, clock, _, _ := testSessionPair(t)
	// The test server uses a deterministic ID, so construct a second server
	// session through the registry directly to exercise the generation guard.
	ref := old.Reference()
	newRef := ref
	newRef.SessionID = "sess_2"
	newRef.ProcessGeneration++
	registry := old.server.config.Registry
	if _, err := registry.Attach(newRef); err != nil {
		t.Fatal(err)
	}
	if err := old.CheckLease(clock.Now()); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("old session check error=%v", err)
	}
	if active, ok := registry.Active(ref.ConnectorID); !ok || active != newRef {
		t.Fatalf("new session was removed by stale check: active=%+v ok=%t", active, ok)
	}
}

func TestHeartbeatMismatchWithdrawsReadinessButRetainsLKG(t *testing.T) {
	serverSession, client, clock, _, first := testSessionPair(t)
	heartbeat, err := client.Heartbeat(clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	heartbeat.LastAppliedGeneration++
	if _, err := serverSession.HandleHeartbeat(context.Background(), heartbeat); !errors.Is(err, ErrSnapshotRequired) {
		t.Fatalf("mismatched heartbeat error=%v", err)
	}
	current, ready, generation := serverSession.Current()
	if ready || generation != 0 || current.ContentHash != first.ContentHash {
		t.Fatalf("heartbeat mismatch state current=%+v ready=%t generation=%d", current, ready, generation)
	}
}

func TestHeartbeatRenewsLeaseWhileInitialSnapshotReadinessIsPending(t *testing.T) {
	serverSession, client, clock, snapshot := testPendingSessionPair(t)
	if _, active, generation := serverSession.Current(); active || generation != 0 {
		t.Fatalf("pending session unexpectedly active: active=%t generation=%d", active, generation)
	}
	previousExpiry := serverSession.Lease().ExpiresAt
	for i := 0; i < 3; i++ {
		clock.Advance(time.Second)
		heartbeat, err := client.Heartbeat(clock.Now())
		if err != nil {
			t.Fatalf("pending heartbeat %d: %v", i, err)
		}
		if heartbeat.LastAppliedGeneration != snapshot.Generation || heartbeat.LastAppliedHash != snapshot.ContentHash {
			t.Fatalf("pending heartbeat %d reported %+v, want generation=%d hash=%s", i, heartbeat, snapshot.Generation, snapshot.ContentHash)
		}
		ack, err := serverSession.HandleHeartbeat(context.Background(), heartbeat)
		if err != nil {
			t.Fatalf("server pending heartbeat %d: %v", i, err)
		}
		if !ack.LeaseExpiresAt.After(previousExpiry) {
			t.Fatalf("pending heartbeat %d did not renew lease: previous=%s next=%s", i, previousExpiry, ack.LeaseExpiresAt)
		}
		previousExpiry = ack.LeaseExpiresAt
		if serverSession.State() != SessionAwaitingReady {
			t.Fatalf("pending heartbeat %d promoted state=%s", i, serverSession.State())
		}
	}
	if _, active := client.Active(); active {
		t.Fatal("pending heartbeats promoted the client candidate")
	}
}

func TestHeartbeatRejectsStaleAndOutOfOrderTimestamps(t *testing.T) {
	serverSession, client, clock, _, first := testSessionPair(t)
	heartbeat, err := client.Heartbeat(clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	firstLease := serverSession.Lease().ExpiresAt
	if _, err := serverSession.HandleHeartbeat(context.Background(), heartbeat); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Second)
	// A retransmission with the same client timestamp is rejected. Strictly
	// increasing timestamps make replay behavior deterministic across replicas.
	if _, err := serverSession.HandleHeartbeat(context.Background(), heartbeat); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("duplicate heartbeat error=%v", err)
	}
	if got := serverSession.Lease().ExpiresAt; !got.Equal(firstLease) {
		t.Fatalf("duplicate heartbeat changed lease: before=%s after=%s", firstLease, got)
	}
	older := heartbeat
	older.SentAt = heartbeat.SentAt.Add(-time.Second)
	if _, err := serverSession.HandleHeartbeat(context.Background(), older); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("out-of-order heartbeat error=%v", err)
	}
	ancient := heartbeat
	ancient.SentAt = clock.Now().Add(-MaxClockSkew - time.Second)
	if _, err := serverSession.HandleHeartbeat(context.Background(), ancient); !errors.Is(err, ErrHeartbeatTimeout) {
		t.Fatalf("stale heartbeat error=%v", err)
	}
	future := heartbeat
	future.SentAt = clock.Now().Add(MaxClockSkew + time.Second)
	if _, err := serverSession.HandleHeartbeat(context.Background(), future); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("future heartbeat error=%v", err)
	}
	current, ready, generation := serverSession.Current()
	if !ready || generation != first.Generation || current.ContentHash != first.ContentHash {
		t.Fatalf("timestamp validation changed LKG: current=%+v ready=%t generation=%d", current, ready, generation)
	}
}

func TestLeaseExpiryDetachesExactRegistryGeneration(t *testing.T) {
	serverSession, _, clock, _, _ := testSessionPair(t)
	ref := serverSession.Reference()
	clock.Advance(2 * time.Minute)
	if err := serverSession.CheckLease(clock.Now()); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("lease error=%v", err)
	}
	if _, ok := serverSession.server.config.Registry.Active(ref.ConnectorID); ok {
		t.Fatal("expired session remained registered")
	}
}

func TestClientCloseSerializesWithActivation(t *testing.T) {
	serverSession, client, _, applier, _ := testSessionPair(t)
	second, err := NewSnapshot("tunnel_1", 2, testConfigPayload(2, "next.preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	second.AccountID, second.ConnectorID, second.SessionID, second.ProcessGeneration = "acct_1", "connector_1", "sess_1", 1
	if err := serverSession.OfferSnapshot(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	ack, err := client.ApplySnapshot(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverSession.HandleAck(context.Background(), ack); err != nil {
		t.Fatal(err)
	}
	applier.activateStarted = make(chan struct{})
	applier.activateRelease = make(chan struct{})
	readyDone := make(chan error, 1)
	go func() {
		_, err := client.MarkReady(true, true, true)
		readyDone <- err
	}()
	select {
	case <-applier.activateStarted:
	case <-time.After(time.Second):
		t.Fatal("activation did not start")
	}
	closeDone := make(chan error, 1)
	events := make(chan string, 2)
	applier.events = events
	go func() {
		err := client.Close(ReasonProtocolClosed)
		events <- "close_done"
		closeDone <- err
	}()
	close(applier.activateRelease)
	select {
	case err := <-readyDone:
		if err != nil {
			t.Fatalf("activation failed after release: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("activation did not complete")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("close failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not complete")
	}
	firstEvent, secondEvent := <-events, <-events
	if firstEvent != "activation_done" || secondEvent != "close_done" {
		t.Fatalf("lifecycle event order = %q, %q", firstEvent, secondEvent)
	}
	if client.State() != SessionClosed {
		t.Fatalf("state=%s, want closed", client.State())
	}
	active, ok := client.Active()
	if !ok || active.Generation != second.Generation {
		t.Fatalf("active=%+v ok=%t, want promoted generation 2", active, ok)
	}
}

func TestCandidateCleanupErrorsAreReported(t *testing.T) {
	serverSession, client, _, applier, _ := testSessionPair(t)
	second, _ := NewSnapshot("tunnel_1", 2, testConfigPayload(2, "next.preview.example.test"))
	second.AccountID, second.ConnectorID, second.SessionID, second.ProcessGeneration = "acct_1", "connector_1", "sess_1", 1
	if err := serverSession.OfferSnapshot(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	ack, err := client.ApplySnapshot(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverSession.HandleAck(context.Background(), ack); err != nil {
		t.Fatal(err)
	}
	activateErr := errors.New("activation failed")
	abortErr := errors.New("abort failed")
	applier.activateErr = activateErr
	applier.abortErr = abortErr
	_, err = client.MarkReady(true, true, true)
	if err == nil || !errors.Is(err, activateErr) || !errors.Is(err, abortErr) {
		t.Fatalf("activation/abort errors were not preserved: %v", err)
	}
	active, ok := client.Active()
	if !ok || active.Generation != 1 {
		t.Fatalf("failed candidate changed active generation: %+v ok=%t", active, ok)
	}
}

func TestCloseAbortErrorIsReported(t *testing.T) {
	serverSession, client, _, applier, _ := testSessionPair(t)
	second, _ := NewSnapshot("tunnel_1", 2, testConfigPayload(2, "next.preview.example.test"))
	second.AccountID, second.ConnectorID, second.SessionID, second.ProcessGeneration = "acct_1", "connector_1", "sess_1", 1
	if err := serverSession.OfferSnapshot(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	ack, err := client.ApplySnapshot(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverSession.HandleAck(context.Background(), ack); err != nil {
		t.Fatal(err)
	}
	abortErr := errors.New("abort failed during close")
	applier.abortErr = abortErr
	err = client.Close(ReasonProtocolClosed)
	if err == nil || !errors.Is(err, abortErr) {
		t.Fatalf("close abort error was not preserved: %v", err)
	}
	if client.State() != SessionClosed {
		t.Fatalf("state=%s, want closed", client.State())
	}
}

func TestDrainStopsAdmissionPreservesIdentityAndCompletes(t *testing.T) {
	serverSession, client, clock, _, _ := testSessionPair(t)
	drainer := &testDrainer{active: 2}
	client.config.Drainer = drainer
	request, err := serverSession.BeginDrain(context.Background(), "drain_1", clock.Now().Add(20*time.Second), true)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := client.HandleDrain(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Status != DrainAccepted || ack.ActiveStreams != 2 || drainer.stopCalls != 1 {
		t.Fatalf("drain acceptance=%+v stopCalls=%d", ack, drainer.stopCalls)
	}
	if err := serverSession.HandleDrainAck(context.Background(), ack); err != nil {
		t.Fatal(err)
	}
	if _, ready, _ := serverSession.Current(); ready {
		t.Fatal("draining session remained eligible")
	}
	drainer.mu.Lock()
	drainer.active = 0
	drainer.mu.Unlock()
	ack, err = client.CompleteDrain(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Status != DrainCompleted || ack.ActiveStreams != 0 || ack.ForcedClose {
		t.Fatalf("completion=%+v", ack)
	}
	if err := serverSession.HandleDrainAck(context.Background(), ack); err != nil {
		t.Fatal(err)
	}
	if err := serverSession.HandleDrainAck(context.Background(), ack); err != nil {
		t.Fatalf("duplicate completion was not idempotent: %v", err)
	}
	if client.State() != SessionDraining {
		t.Fatalf("client state=%s, want draining until transport closes", client.State())
	}
}

func TestRejectedDrainRestoresReadyEligibility(t *testing.T) {
	serverSession, client, clock, _, _ := testSessionPair(t)
	request, err := serverSession.BeginDrain(context.Background(), "drain_rejected", clock.Now().Add(20*time.Second), true)
	if err != nil {
		t.Fatal(err)
	}
	ack := DrainAck{AccountID: request.AccountID, TunnelID: request.TunnelID, ConnectorID: request.ConnectorID, SessionID: request.SessionID, ProcessGeneration: request.ProcessGeneration, DrainID: request.DrainID, Generation: request.Generation, ContentHash: request.ContentHash, Status: DrainRejected, Code: CodeDrainRejected}
	if err := serverSession.HandleDrainAck(context.Background(), ack); !errors.Is(err, ErrDrainRejected) {
		t.Fatalf("rejected drain error=%v", err)
	}
	if state := serverSession.State(); state != SessionReady {
		t.Fatalf("server state=%s, want ready after rejection", state)
	}
	if _, ready, _ := serverSession.Current(); !ready {
		t.Fatal("rejected drain withdrew ready eligibility")
	}
	_ = client
}

func TestDrainForcedCloseIsTypedAndGenerationBound(t *testing.T) {
	serverSession, client, clock, _, _ := testSessionPair(t)
	drainer := &testDrainer{active: 3}
	client.config.Drainer = drainer
	request, err := serverSession.BeginDrain(context.Background(), "drain_force", clock.Now().Add(20*time.Second), true)
	if err != nil {
		t.Fatal(err)
	}
	stale := request
	stale.Generation++
	if _, err := client.HandleDrain(context.Background(), stale); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale drain error=%v", err)
	}
	if _, err := client.HandleDrain(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	ack, err := client.CompleteDrain(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Status != DrainForced || !ack.ForcedClose || ack.Code != CodeDrainTimeout || drainer.forceCalls != 1 {
		t.Fatalf("forced completion=%+v forceCalls=%d", ack, drainer.forceCalls)
	}
	if err := serverSession.HandleDrainAck(context.Background(), ack); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CompleteDrain(context.Background(), true); err != nil {
		t.Fatalf("forced completion was not idempotent: %v", err)
	}
}

func TestDrainHookFailureRejectsWithoutWithdrawingReadySession(t *testing.T) {
	serverSession, client, clock, _, _ := testSessionPair(t)
	drainer := &testDrainer{stopErr: errors.New("stop admission failed")}
	client.config.Drainer = drainer
	request, err := serverSession.BeginDrain(context.Background(), "drain_reject", clock.Now().Add(20*time.Second), false)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := client.HandleDrain(context.Background(), request)
	if err == nil || !errors.Is(err, ErrDrainRejected) || ack.Status != DrainRejected || ack.Code != CodeDrainRejected {
		t.Fatalf("drain rejection ack=%+v err=%v", ack, err)
	}
	if client.State() != SessionReady {
		t.Fatalf("client state=%s, want ready after rejected drain", client.State())
	}
}
