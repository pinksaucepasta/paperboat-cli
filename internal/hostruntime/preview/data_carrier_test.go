package preview

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
)

func TestDataCarrierPreviewHubDispatchesInterleavedRoutesWithoutCrossConsumption(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	identity := testPreviewCarrierIdentity(1)
	pair := newPreviewCarrierPair(t, ctx, identity)
	defer pair.close()

	hub, err := NewDataCarrierPreviewHub(ctx, DataCarrierPreviewHubConfig{Active: pair.active, Identity: identity, QueueDepth: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	registrationA, err := hub.Register("preview_a")
	if err != nil {
		t.Fatal(err)
	}
	registrationB, err := hub.Register("preview_b")
	if err != nil {
		t.Fatal(err)
	}

	openA := testPreviewStreamOpen(identity, "preview_a", "request_a_1")
	openB := testPreviewStreamOpen(identity, "preview_b", "request_b_1")
	streamA := pair.openEdgeStream(t, openA)
	streamB := pair.openEdgeStream(t, openB)
	acceptedA, acceptedOpenA := acceptPreviewRegistration(t, registrationA)
	acceptedB, acceptedOpenB := acceptPreviewRegistration(t, registrationB)
	if acceptedOpenA != openA || acceptedOpenB != openB {
		t.Fatalf("interleaved dispatch crossed routes: A=%+v B=%+v", acceptedOpenA, acceptedOpenB)
	}
	_ = streamA.Close()
	_ = streamB.Close()
	_ = acceptedA.Close()
	_ = acceptedB.Close()

	if err := registrationA.Close(); err != nil {
		t.Fatal(err)
	}
	closedCtx, closeCancel := context.WithTimeout(ctx, time.Second)
	defer closeCancel()
	if _, _, err := registrationA.Accept(closedCtx); !errors.Is(err, ErrDataCarrierPreviewClosed) {
		t.Fatalf("closed route accept error = %v, want %v", err, ErrDataCarrierPreviewClosed)
	}
	openB2 := testPreviewStreamOpen(identity, "preview_b", "request_b_2")
	streamB2 := pair.openEdgeStream(t, openB2)
	acceptedB2, acceptedOpenB2 := acceptPreviewRegistration(t, registrationB)
	if acceptedOpenB2 != openB2 {
		t.Fatalf("remaining route open = %+v, want %+v", acceptedOpenB2, openB2)
	}
	_ = streamB2.Close()
	_ = acceptedB2.Close()
}

func TestDataCarrierPreviewHubReplacementFencesOldGeneration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	identityOne := testPreviewCarrierIdentity(1)
	pairOne := newPreviewCarrierPair(t, ctx, identityOne)
	defer pairOne.close()
	hubOne, err := NewDataCarrierPreviewHub(ctx, DataCarrierPreviewHubConfig{Active: pairOne.active, Identity: identityOne})
	if err != nil {
		t.Fatal(err)
	}
	registrationOne, err := hubOne.Register("preview_replace")
	if err != nil {
		t.Fatal(err)
	}

	if err := hubOne.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := registrationOne.Accept(ctx); !errors.Is(err, ErrDataCarrierPreviewHubClosed) {
		t.Fatalf("old generation accept error = %v, want %v", err, ErrDataCarrierPreviewHubClosed)
	}
	// A stale stream is never dispatched after the old hub has been fenced.
	stale := pairOne.openEdgeStream(t, testPreviewStreamOpen(identityOne, "preview_replace", "stale_request"))
	_ = stale.Close()

	identityTwo := testPreviewCarrierIdentity(2)
	pairTwo := newPreviewCarrierPair(t, ctx, identityTwo)
	defer pairTwo.close()
	hubTwo, err := NewDataCarrierPreviewHub(ctx, DataCarrierPreviewHubConfig{Active: pairTwo.active, Identity: identityTwo})
	if err != nil {
		t.Fatal(err)
	}
	defer hubTwo.Close()
	registrationTwo, err := hubTwo.Register("preview_replace")
	if err != nil {
		t.Fatal(err)
	}
	current := testPreviewStreamOpen(identityTwo, "preview_replace", "current_request")
	stream := pairTwo.openEdgeStream(t, current)
	accepted, acceptedOpen := acceptPreviewRegistration(t, registrationTwo)
	if acceptedOpen != current {
		t.Fatalf("replacement open = %+v, want %+v", acceptedOpen, current)
	}
	_ = stream.Close()
	_ = accepted.Close()
}

func TestDataCarrierPreviewHubCloseBeforeRegistrationDoesNotBlock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	identity := testPreviewCarrierIdentity(1)
	pair := newPreviewCarrierPair(t, ctx, identity)
	defer pair.close()
	hub, err := NewDataCarrierPreviewHub(ctx, DataCarrierPreviewHubConfig{Active: pair.active, Identity: identity})
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- hub.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("hub close blocked before first registration")
	}
}

func TestDataCarrierPreviewCarrierPublishesReadyProjection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	identity := testPreviewCarrierIdentity(1)
	pair := newPreviewCarrierPair(t, ctx, identity)
	defer pair.close()
	hub, err := NewDataCarrierPreviewHub(ctx, DataCarrierPreviewHubConfig{Active: pair.active, Identity: identity})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	carrier, err := NewDataCarrierPreviewCarrier(DataCarrierPreviewCarrierConfig{
		Hub:      hub,
		Identity: identity,
		DialOrigin: func(context.Context, LeaseTarget) (io.ReadWriteCloser, error) {
			return &previewTestOrigin{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	lease := Lease{ID: "preview_ready", Target: LeaseTarget{Scheme: "tcp", Address: "127.0.0.1:1"}, State: "registering", AllocationState: "pending", EdgeState: "pending", OriginState: "pending"}
	ready := make(chan Lease, 1)
	runDone := make(chan error, 1)
	go func() {
		runDone <- carrier.Run(ctx, lease, func(observed Lease) error {
			ready <- observed
			return nil
		})
	}()
	select {
	case observed := <-ready:
		if observed.State != "ready" || observed.AllocationState != "ready" || observed.EdgeState != "ready" || observed.OriginState != "ready" {
			t.Fatalf("ready projection = %+v", observed)
		}
		if lease.State != "registering" || lease.AllocationState != "pending" || lease.EdgeState != "pending" || lease.OriginState != "pending" {
			t.Fatalf("input lease mutated = %+v", lease)
		}
	case <-time.After(time.Second):
		t.Fatal("carrier did not report readiness")
	}
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("carrier run after cancel: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("carrier did not stop after cancellation")
	}
	_ = carrier.Close(context.Background())
}

func TestDataCarrierPreviewCarrierReportsOriginStreamFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	identity := testPreviewCarrierIdentity(1)
	pair := newPreviewCarrierPair(t, ctx, identity)
	defer pair.close()
	hub, err := NewDataCarrierPreviewHub(ctx, DataCarrierPreviewHubConfig{Active: pair.active, Identity: identity})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	streamFailure := errors.New("origin read failed")
	observed := make(chan error, 1)
	carrier, err := NewDataCarrierPreviewCarrier(DataCarrierPreviewCarrierConfig{
		Hub: hub, Identity: identity,
		DialOrigin: func(context.Context, LeaseTarget) (io.ReadWriteCloser, error) {
			return &failingPreviewOrigin{err: streamFailure}, nil
		},
		ObserveStreamError: func(err error) { observed <- err },
	})
	if err != nil {
		t.Fatal(err)
	}
	lease := Lease{ID: "preview_failure", Target: LeaseTarget{Scheme: "tcp", Address: "127.0.0.1:1"}}
	ready := make(chan struct{})
	runDone := make(chan error, 1)
	go func() {
		runDone <- carrier.Run(ctx, lease, func(Lease) error {
			close(ready)
			return nil
		})
	}()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("carrier did not become ready")
	}
	stream := pair.openEdgeStream(t, testPreviewStreamOpen(identity, lease.ID, "request_failure"))
	defer stream.Close()
	select {
	case err := <-observed:
		var retryable *RetryableCarrierError
		if !errors.Is(err, ErrDataCarrierPreviewForward) || !errors.Is(err, streamFailure) || !errors.As(err, &retryable) {
			t.Fatalf("observed stream error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stream failure was hidden")
	}
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("carrier did not stop")
	}
}

type failingPreviewOrigin struct{ err error }

func (o *failingPreviewOrigin) Read([]byte) (int, error) { return 0, o.err }
func (*failingPreviewOrigin) Write(payload []byte) (int, error) {
	return len(payload), nil
}
func (*failingPreviewOrigin) Close() error { return nil }

type previewTestOrigin struct{ bytes.Buffer }

func (*previewTestOrigin) Close() error { return nil }

type previewCarrierPair struct {
	active *connector.ActiveDataCarrier
	edge   *connector.DataCarrier
}

func newPreviewCarrierPair(t *testing.T, ctx context.Context, identity connector.DataCarrierIdentity) *previewCarrierPair {
	t.Helper()
	poolConfig := connector.DefaultDataCarrierPoolConfig()
	poolConfig.MaximumCarriers = 1
	poolConfig.Preferred = connector.TCPMux
	poolConfig.Fallback = connector.TCPMux
	poolConfig.SingleTransport = true
	poolConfig.FailureDomains = []string{"domain-a"}
	poolConfig.Session = identity
	carrierConfig := poolConfig.Carrier
	pair := &previewCarrierPair{}
	dialer := connector.DataCarrierDialer(func(_ context.Context, request connector.DataCarrierDialRequest) (connector.DataCarrierDialResult, error) {
		local, remote := net.Pipe()
		edge, err := connector.NewDataCarrierServer(ctx, remote, carrierConfig, connector.DataCarrierAdmission{
			Identity:  identity,
			Authorize: func(context.Context, connector.StreamOpen) error { return nil },
		})
		if err != nil {
			_ = local.Close()
			_ = remote.Close()
			return connector.DataCarrierDialResult{}, err
		}
		pair.edge = edge
		return connector.DataCarrierDialResult{Link: local, PeerIdentity: identity, Transport: request.Transport, EdgeID: request.EdgeID, FailureDomain: request.FailureDomain}, nil
	})
	prepared, err := connector.PrepareDataCarrier(ctx, identity, poolConfig, dialer)
	if err != nil {
		t.Fatalf("prepare carrier: %v", err)
	}
	active, err := prepared.Activate(ctx)
	if err != nil {
		t.Fatalf("activate carrier: %v", err)
	}
	pair.active = active
	return pair
}

func (p *previewCarrierPair) openEdgeStream(t *testing.T, open connector.StreamOpen) interface{ Close() error } {
	t.Helper()
	if p == nil || p.edge == nil {
		t.Fatal("missing edge carrier")
	}
	stream, err := p.edge.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("open edge stream: %v", err)
	}
	if err := connectorprotocol.WriteStreamOpen(stream, open); err != nil {
		_ = stream.Close()
		t.Fatalf("write stream open: %v", err)
	}
	return stream
}

func (p *previewCarrierPair) close() {
	if p == nil {
		return
	}
	if p.active != nil {
		_ = p.active.Close(context.Background())
	}
	if p.edge != nil {
		_ = p.edge.Close()
	}
}

func acceptPreviewRegistration(t *testing.T, registration *DataCarrierPreviewRegistration) (*connector.DataCarrierStream, connector.StreamOpen) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stream, open, err := registration.Accept(ctx)
	if err != nil {
		t.Fatalf("accept route stream: %v", err)
	}
	return stream, open
}

func testPreviewCarrierIdentity(generation uint64) connector.DataCarrierIdentity {
	return connector.DataCarrierIdentity{AccountID: "account_01", HostID: "host_01", TunnelID: "tunnel_01", ConnectorID: "connector_01", SessionID: "session_01", ProcessGeneration: 1, Generation: generation}
}

func testPreviewStreamOpen(identity connector.DataCarrierIdentity, routeID, requestID string) connector.StreamOpen {
	return connector.StreamOpen{Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion, AccountID: identity.AccountID, TunnelID: identity.TunnelID, ConnectorID: identity.ConnectorID, SessionID: identity.SessionID, ProcessGeneration: identity.ProcessGeneration, Generation: identity.Generation, RouteID: routeID, RequestID: requestID, Kind: "https"}
}
