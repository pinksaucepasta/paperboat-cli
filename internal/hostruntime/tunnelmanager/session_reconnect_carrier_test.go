package tunnelmanager

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
)

type reconnectCarrierFactory struct {
	mu         sync.Mutex
	requests   []ApplyRequest
	candidates []Candidate
}

func (f *reconnectCarrierFactory) Prepare(_ context.Context, request ApplyRequest) (Candidate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, request)
	if len(f.candidates) == 0 {
		return nil, errors.New("no reconnect candidate")
	}
	candidate := f.candidates[0]
	f.candidates = f.candidates[1:]
	return candidate, nil
}

type reconnectCarrierCandidate struct {
	active       *reconnectCarrierActive
	probeStarted chan struct{}
	releaseProbe <-chan struct{}
	once         sync.Once
}

func (c *reconnectCarrierCandidate) ProbeOrigins(ctx context.Context) (ProbeResult, error) {
	if c.probeStarted != nil {
		c.once.Do(func() { close(c.probeStarted) })
	}
	if c.releaseProbe == nil {
		return ProbeResult{Ready: true}, nil
	}
	select {
	case <-c.releaseProbe:
		return ProbeResult{Ready: true}, nil
	case <-ctx.Done():
		return ProbeResult{}, ctx.Err()
	}
}

func (c *reconnectCarrierCandidate) Activate(context.Context) (Active, error) {
	if c == nil || c.active == nil {
		return nil, ErrConnectorUnavailable
	}
	return c.active, nil
}

func (c *reconnectCarrierCandidate) Abort(context.Context) error { return nil }

type reconnectCarrierActive struct {
	base    *fakeActive
	carrier *connector.ActiveDataCarrier
}

func (a *reconnectCarrierActive) TunnelID() string                { return a.base.TunnelID() }
func (a *reconnectCarrierActive) ConnectorID() string             { return a.base.ConnectorID() }
func (a *reconnectCarrierActive) Generation() uint64              { return a.base.Generation() }
func (a *reconnectCarrierActive) ContentHash() string             { return a.base.ContentHash() }
func (a *reconnectCarrierActive) Drain(ctx context.Context) error { return a.base.Drain(ctx) }
func (a *reconnectCarrierActive) Close(ctx context.Context) error { return a.base.Close(ctx) }
func (a *reconnectCarrierActive) ActiveDataCarrier() *connector.ActiveDataCarrier {
	if a == nil {
		return nil
	}
	return a.carrier
}

func newConnectedReconnectCarrier(t *testing.T, identity connector.DataCarrierIdentity) (*connector.ActiveDataCarrier, func()) {
	t.Helper()
	carrierConfig := connector.DefaultDataCarrierConfig()
	poolConfig := connector.DefaultDataCarrierPoolConfig()
	poolConfig.MaximumCarriers = 1
	poolConfig.QueueDepth = 1
	poolConfig.Preferred = connector.TCPMux
	poolConfig.Fallback = connector.TCPMux
	poolConfig.SingleTransport = true
	poolConfig.EdgeID = "edge-reconnect"
	poolConfig.FailureDomains = []string{"domain-reconnect"}
	poolConfig.Session = identity
	poolConfig.Carrier = carrierConfig

	var edge *connector.DataCarrier
	dialer := connector.DataCarrierDialer(func(_ context.Context, request connector.DataCarrierDialRequest) (connector.DataCarrierDialResult, error) {
		local, remote := net.Pipe()
		var err error
		edge, err = connector.NewDataCarrierServer(context.Background(), remote, carrierConfig, connector.DataCarrierAdmission{
			Identity:  request.Identity,
			Authorize: func(context.Context, connector.StreamOpen) error { return nil },
		})
		if err != nil {
			_ = local.Close()
			_ = remote.Close()
			return connector.DataCarrierDialResult{}, err
		}
		return connector.DataCarrierDialResult{Link: local, PeerIdentity: request.Identity, Transport: request.Transport, EdgeID: request.EdgeID, FailureDomain: request.FailureDomain}, nil
	})
	prepared, err := connector.PrepareDataCarrier(context.Background(), identity, poolConfig, dialer)
	if err != nil {
		t.Fatalf("prepare reconnect carrier: %v", err)
	}
	active, err := prepared.Activate(context.Background())
	if err != nil {
		_ = prepared.Abort(context.Background())
		t.Fatalf("activate reconnect carrier: %v", err)
	}
	cleanup := func() {
		_ = active.Close(context.Background())
		if edge != nil {
			_ = edge.Close()
		}
	}
	return active, cleanup
}

func TestManagerReplacesCarrierAfterControlReconnectWithoutConfigChange(t *testing.T) {
	oldIdentity := connector.DataCarrierIdentity{AccountID: "account_01", HostID: "host_01", TunnelID: "tunnel_01", ConnectorID: "connector_01", SessionID: "session-old", ProcessGeneration: 7, Generation: 1}
	newIdentity := oldIdentity
	newIdentity.SessionID = "session-new"
	newIdentity.ProcessGeneration = 8
	oldCarrier, cleanupOld := newConnectedReconnectCarrier(t, oldIdentity)
	newCarrier, cleanupNew := newConnectedReconnectCarrier(t, newIdentity)
	t.Cleanup(cleanupOld)
	t.Cleanup(cleanupNew)

	store := &memoryStateStore{state: tunnelState(t, 1, 1), revision: 4}
	oldActive := &reconnectCarrierActive{base: &fakeActive{tunnelID: "tunnel_01", connectorID: "connector_01", generation: 1, hash: store.state.Tunnels[0].DesiredSnapshot.ContentHash}, carrier: oldCarrier}
	newActive := &reconnectCarrierActive{base: &fakeActive{tunnelID: "tunnel_01", connectorID: "connector_01", generation: 1, hash: store.state.Tunnels[0].DesiredSnapshot.ContentHash}, carrier: newCarrier}
	probeStarted := make(chan struct{})
	releaseProbe := make(chan struct{})
	factory := &reconnectCarrierFactory{candidates: []Candidate{
		&reconnectCarrierCandidate{active: oldActive},
		&reconnectCarrierCandidate{active: newActive, probeStarted: probeStarted, releaseProbe: releaseProbe},
	}}
	manager := newTestManager(t, store, factory, time.Date(2026, 9, 2, 5, 0, 0, 0, time.UTC), func(Observation) {})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())

	state, _, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := state.Tunnels[0].DesiredSnapshot
	manager.RecordControlSessionBinding(oldIdentity.AccountID, oldIdentity.TunnelID, oldIdentity.ConnectorID, oldIdentity.SessionID, oldIdentity.ProcessGeneration, snapshot.Generation, snapshot.ContentHash)
	if err := manager.ReconcileNow(context.Background()); err != nil {
		t.Fatalf("same-session reconcile: %v", err)
	}
	factory.mu.Lock()
	if len(factory.requests) != 1 {
		factory.mu.Unlock()
		t.Fatalf("same-session prepared %d carriers, want 1", len(factory.requests))
	}
	factory.mu.Unlock()

	// A server disconnect creates a new authenticated session/process binding,
	// but the desired config and LKG bytes remain unchanged. The manager must
	// stage and probe the replacement before touching the old active carrier.
	manager.RecordControlSessionBinding(newIdentity.AccountID, newIdentity.TunnelID, newIdentity.ConnectorID, newIdentity.SessionID, newIdentity.ProcessGeneration, snapshot.Generation, snapshot.ContentHash)
	reconcileDone := make(chan error, 1)
	go func() { reconcileDone <- manager.ReconcileNow(context.Background()) }()
	select {
	case <-probeStarted:
	case <-time.After(time.Second):
		t.Fatal("replacement carrier was not staged")
	}
	if oldActive.base.closes != 0 || oldActive.base.drains != 0 {
		t.Fatalf("old carrier was closed before replacement readiness: drains=%d closes=%d", oldActive.base.drains, oldActive.base.closes)
	}
	close(releaseProbe)
	if err := <-reconcileDone; err != nil {
		t.Fatalf("replacement reconcile: %v", err)
	}
	active, ok := manager.ActiveForTunnel("tunnel_01")
	if !ok || active != newActive {
		t.Fatalf("published active=%v/%v, want replacement %v", active, ok, newActive)
	}
	if oldActive.base.drains != 1 || oldActive.base.closes != 1 {
		t.Fatalf("old carrier lifecycle=%d/%d, want one drain/close", oldActive.base.drains, oldActive.base.closes)
	}
	factory.mu.Lock()
	requests := append([]ApplyRequest(nil), factory.requests...)
	factory.mu.Unlock()
	if len(requests) != 2 || requests[1].Snapshot.Generation != snapshot.Generation || requests[1].Recovery {
		t.Fatalf("replacement requests=%+v", requests)
	}
	finalState, _, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if finalState.Tunnels[0].AppliedGeneration != 1 || finalState.Tunnels[0].LastKnownGood == nil || finalState.Tunnels[0].LastKnownGood.ContentHash != snapshot.ContentHash {
		t.Fatalf("same-config replacement changed LKG=%+v", finalState.Tunnels[0])
	}
}

var _ ActiveCarrierProvider = (*reconnectCarrierActive)(nil)
var _ Candidate = (*reconnectCarrierCandidate)(nil)
var _ Factory = (*reconnectCarrierFactory)(nil)
