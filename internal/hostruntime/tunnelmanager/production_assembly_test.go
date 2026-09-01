package tunnelmanager

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connectorrotation"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
)

type assemblyClock struct{ now time.Time }

func (c assemblyClock) Now() time.Time { return c.now }

type assemblyOrigins struct{}

func (assemblyOrigins) ProbeOrigin(context.Context, hoststate.TunnelConfigRoute) error { return nil }

type assemblyDrainer struct{}

func (assemblyDrainer) StopNewStreams(context.Context) error          { return nil }
func (assemblyDrainer) ActiveStreams(context.Context) (uint32, error) { return 0, nil }
func (assemblyDrainer) ForceClose(context.Context) error              { return nil }

func newProductionAssemblyConfig(t *testing.T) ProductionAssemblyConfig {
	config, _ := newProductionAssemblyConfigWithSigner(t)
	return config
}

func newProductionAssemblyConfigWithSigner(t *testing.T) (ProductionAssemblyConfig, ed25519.PrivateKey) {
	t.Helper()
	now := time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := connectorprotocol.IdentityThumbprint(public)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := connectorprotocol.IdentityKeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	identity := connector.DataCarrierIdentity{AccountID: "account_01", HostID: "host_01", TunnelID: "tunnel_01", ConnectorID: "connector_01", SessionID: "session_01", ProcessGeneration: 2, Generation: 1}
	auth := connectorprotocol.AuthRequest{
		AccountID: identity.AccountID, TunnelID: identity.TunnelID, ConnectorID: identity.ConnectorID, HostID: identity.HostID,
		IdentityKeyID: keyID, IdentityKeyThumbprint: thumbprint, ProcessGeneration: identity.ProcessGeneration, CredentialGeneration: 1,
		Nonce: "assembly-auth-nonce-01", IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	auth, err = connectorprotocol.SignAuthProof(auth, func(payload []byte) []byte { return ed25519.Sign(private, payload) })
	if err != nil {
		t.Fatal(err)
	}
	source, err := connector.NewDataCarrierSessionSource(identity, connector.DataCarrierPoolConfig{}, connector.DataCarrierDialer(func(context.Context, connector.DataCarrierDialRequest) (connector.DataCarrierDialResult, error) {
		return connector.DataCarrierDialResult{}, errors.New("dialer must not run during assembly")
	}))
	if err != nil {
		t.Fatal(err)
	}
	return ProductionAssemblyConfig{
		Production:       ProductionConfig{StateRoot: t.TempDir(), HostID: identity.HostID, Report: func(Observation) {}},
		StableEndpointID: testManagedTunnelEndpointID, Clock: assemblyClock{now: now}, SessionSource: source, Origins: assemblyOrigins{},
		InitialConnector: &hoststate.Connector{ID: identity.ConnectorID, TunnelID: identity.TunnelID, HostID: identity.HostID, Credential: hoststate.CredentialReference{Reference: "keychain://paperboat/connectors/connector_01", Generation: identity.Generation}, RotationGeneration: identity.Generation},
		Control: connectorrotation.ControlSessionConfig{
			Hello: connectorprotocol.Hello{
				Protocol: connectorprotocol.ProtocolName, MinVersion: connectorprotocol.ProtocolVersion, MaxVersion: connectorprotocol.ProtocolVersion,
				AccountID: identity.AccountID, TunnelID: identity.TunnelID, ConnectorID: identity.ConnectorID, HostID: identity.HostID,
				ProcessGeneration: identity.ProcessGeneration,
				Capabilities:      []string{connectorprotocol.CapabilitySnapshot, connectorprotocol.CapabilityDelta, connectorprotocol.CapabilityAck, connectorprotocol.CapabilityHeartbeat, connectorprotocol.CapabilityRenewal},
				Auth:              auth,
			},
			Drainer: assemblyDrainer{},
			Renewal: connectorrotation.CredentialRenewalSourceFunc(func(context.Context, time.Time) (string, string, error) {
				return "renewal-nonce-01", "renewal-proof-01", nil
			}),
			Clock: assemblyClock{now: now},
		},
		HelloRequestID: "hello-assembly-01",
	}, private
}

func TestOpenProductionAssemblySharesManagerStoreAndControlBoundary(t *testing.T) {
	config := newProductionAssemblyConfig(t)
	assembly, status, err := OpenProductionAssembly(config)
	if err != nil || status.Degraded {
		t.Fatalf("open assembly: status=%+v err=%v", status, err)
	}
	if assembly.Manager == nil || assembly.Factory == nil || assembly.Applier == nil || assembly.Control == nil {
		t.Fatalf("assembly is incomplete: %+v", assembly)
	}
	if assembly.Applier.Manager != assembly.Manager.Manager || assembly.Control.Session() == nil || !assembly.Control.HasSnapshotReadiness() {
		t.Fatal("assembly did not use one manager/applier/control composition")
	}
	if _, _, err := OpenProductionAssembly(config); !errors.Is(err, hoststate.ErrLocked) {
		t.Fatalf("second assembly must not open a second state store: %v", err)
	}
	if err := assembly.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if got := assembly.ResourceCounts()["tunnels"]; got != 0 {
		t.Fatalf("empty durable state has active tunnel count %d", got)
	}
	if err := assembly.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	reopened, _, err := OpenProductionAssembly(config)
	if err != nil {
		t.Fatalf("state lock was not released after shutdown: %v", err)
	}
	if err := reopened.Shutdown(context.Background()); err != nil {
		t.Fatalf("reopened shutdown: %v", err)
	}
}

func TestOpenProductionAssemblyRequiresRenewableCredentialSource(t *testing.T) {
	config := newProductionAssemblyConfig(t)
	config.Control.Renewal = nil
	if _, _, err := OpenProductionAssembly(config); !errors.Is(err, ErrProductionCredentialMissing) {
		t.Fatalf("missing renewal source error = %v", err)
	}
}

func TestOpenProductionAssemblyRequiresCanonicalStableEndpointID(t *testing.T) {
	for _, stableEndpointID := range []string{"", "endpoint_01", "tep_0123456789abcdef"} {
		t.Run(stableEndpointID, func(t *testing.T) {
			config := newProductionAssemblyConfig(t)
			config.StableEndpointID = stableEndpointID
			if _, _, err := OpenProductionAssembly(config); !errors.Is(err, hoststate.ErrInvalidState) {
				t.Fatalf("stable endpoint ID %q error = %v, want hoststate.ErrInvalidState", stableEndpointID, err)
			}
		})
	}
}

func TestLiveDataCarrierSessionSourceBindsDurableApplyRequest(t *testing.T) {
	config := newProductionAssemblyConfig(t)
	source := liveDataCarrierSessionSource{source: config.SessionSource, expectedAccountID: config.Control.Hello.AccountID}
	request := ApplyRequest{
		Tunnel:    hoststate.Tunnel{ID: "tunnel_01"},
		Connector: hoststate.Connector{ID: "connector_01", TunnelID: "tunnel_01", HostID: "host_01"},
		Snapshot:  hoststate.ConfigSnapshot{Generation: 1},
	}
	prepared, err := source.PrepareDataCarrier(context.Background(), request)
	if err != nil {
		t.Fatalf("matching source identity rejected: %v", err)
	}
	if prepared.Identity.AccountID != "account_01" || prepared.Identity.SessionID != "session_01" {
		t.Fatalf("prepared identity = %+v", prepared.Identity)
	}
	request.Snapshot.Generation = 2
	if _, err := source.PrepareDataCarrier(context.Background(), request); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("stale apply request error = %v", err)
	}
}

func TestProductionAssemblyRunsOneControlLoopAndCancelsItBeforeStoreShutdown(t *testing.T) {
	assembly, _, err := OpenProductionAssembly(newProductionAssemblyConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	defer server.Close()
	runDone := make(chan error, 1)
	go func() { runDone <- assembly.RunControl(context.Background(), client, "hello-assembly-01") }()
	if _, err := connectorprotocol.ReadFrame(server); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	if err := assembly.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := <-runDone; err == nil {
		t.Fatal("control loop returned success after lifecycle cancellation")
	}
	secondServer, secondClient := net.Pipe()
	defer secondServer.Close()
	if err := assembly.RunControl(context.Background(), secondClient, "hello-assembly-02"); !errors.Is(err, ErrProductionControlStarted) {
		t.Fatalf("second control loop error = %v", err)
	}
}

func TestProductionAssemblyReconnectsWithFreshControlSessionAfterDisconnect(t *testing.T) {
	config, private := newProductionAssemblyConfigWithSigner(t)
	firstServer, firstClient := net.Pipe()
	secondServer, secondClient := net.Pipe()
	defer firstServer.Close()
	defer secondServer.Close()
	var streamMu sync.Mutex
	streamProviderCalls := 0
	config.ControlStream = func(ctx context.Context) (io.ReadWriteCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		streamMu.Lock()
		defer streamMu.Unlock()
		streamProviderCalls++
		if streamProviderCalls == 1 {
			return firstClient, nil
		}
		if streamProviderCalls == 2 {
			return secondClient, nil
		}
		return nil, ErrProductionControlMissing
	}
	config.ControlSessionFactory = func(context.Context, *CoordinatedConfigApplier) (connectorrotation.ControlSessionConfig, error) {
		fresh := config.Control
		auth := fresh.Hello.Auth
		auth.Nonce = "reconnect-auth-nonce-02"
		auth.IssuedAt = config.Clock.Now()
		auth.ExpiresAt = config.Clock.Now().Add(time.Minute)
		var err error
		auth, err = connectorprotocol.SignAuthProof(auth, func(payload []byte) []byte { return ed25519.Sign(private, payload) })
		if err != nil {
			return connectorrotation.ControlSessionConfig{}, err
		}
		fresh.Hello.Auth = auth
		return fresh, nil
	}
	reports := make(chan Observation, 4)
	config.Production.Report = func(observation Observation) {
		select {
		case reports <- observation:
		default:
		}
	}
	assembly, _, err := OpenProductionAssembly(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := assembly.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	firstHello, err := connectorprotocol.ReadFrame(firstServer)
	if err != nil {
		t.Fatalf("read first hello: %v", err)
	}
	if firstHello.Type != connectorprotocol.MessageHello {
		t.Fatalf("first frame = %+v", firstHello)
	}
	if err := firstServer.Close(); err != nil {
		t.Fatal(err)
	}
	if setter, ok := secondServer.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = setter.SetReadDeadline(time.Now().Add(5 * time.Second))
	}
	secondHello, err := connectorprotocol.ReadFrame(secondServer)
	if err != nil {
		t.Fatalf("read reconnect hello: %v", err)
	}
	if secondHello.Type != connectorprotocol.MessageHello {
		t.Fatalf("reconnect frame = %+v", secondHello)
	}
	var firstHelloPayload, secondHelloPayload connectorprotocol.Hello
	if err := firstHello.DecodePayload(&firstHelloPayload); err != nil {
		t.Fatalf("decode first hello: %v", err)
	}
	if err := secondHello.DecodePayload(&secondHelloPayload); err != nil {
		t.Fatalf("decode reconnect hello: %v", err)
	}
	if firstHelloPayload.Auth.Nonce == secondHelloPayload.Auth.Nonce || firstHelloPayload.Auth.IdentityKeyID != secondHelloPayload.Auth.IdentityKeyID || firstHelloPayload.Auth.IdentityKeyThumbprint != secondHelloPayload.Auth.IdentityKeyThumbprint || firstHelloPayload.Auth.SignedProof == secondHelloPayload.Auth.SignedProof || firstHelloPayload.AccountID != secondHelloPayload.AccountID || firstHelloPayload.TunnelID != secondHelloPayload.TunnelID || firstHelloPayload.ConnectorID != secondHelloPayload.ConnectorID || firstHelloPayload.HostID != secondHelloPayload.HostID {
		t.Fatalf("reconnect auth identity/nonce = first=%+v second=%+v", firstHelloPayload, secondHelloPayload)
	}
	freshWelcome := connectorprotocol.Welcome{
		Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion, SessionID: "session-reconnected-01",
		Capabilities:     config.Control.Hello.Capabilities,
		Lease:            connectorprotocol.Lease{SessionID: "session-reconnected-01", ExpiresAt: config.Clock.Now().Add(time.Minute), HeartbeatIntervalMS: 10000},
		RequiresSnapshot: true, ServerTime: config.Clock.Now(),
	}
	freshWelcomeFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageWelcome, "welcome-reconnect-01", freshWelcome)
	if err != nil {
		t.Fatalf("fresh welcome frame: %v", err)
	}
	if err := connectorprotocol.WriteFrame(secondServer, freshWelcomeFrame); err != nil {
		t.Fatalf("write fresh welcome: %v", err)
	}
	acceptedFreshWelcome := false
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		assembly.controlMu.Lock()
		current := assembly.Control
		assembly.controlMu.Unlock()
		if current != nil && current.Session() != nil && current.Session().State() == connectorprotocol.SessionAwaitingSnapshot {
			acceptedFreshWelcome = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !acceptedFreshWelcome {
		t.Fatal("fresh reconnect Welcome was not accepted")
	}
	streamMu.Lock()
	gotCalls := streamProviderCalls
	streamMu.Unlock()
	if gotCalls != 2 {
		t.Fatalf("control stream provider calls=%d, want 2", gotCalls)
	}
	select {
	case observation := <-reports:
		if observation.Code != CodeControlUnavailable || !observation.Retryable {
			t.Fatalf("disconnect observation = %+v", observation)
		}
	case <-time.After(time.Second):
		t.Fatal("disconnect was not reported before reconnect")
	}
	if err := assembly.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestProductionAssemblyShutdownCancelsControlReconnectBackoff(t *testing.T) {
	config := newProductionAssemblyConfig(t)
	server, client := net.Pipe()
	defer server.Close()
	var calls int
	config.ControlStream = func(ctx context.Context) (io.ReadWriteCloser, error) {
		calls++
		if calls == 1 {
			return client, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	config.ControlSessionFactory = func(context.Context, *CoordinatedConfigApplier) (connectorrotation.ControlSessionConfig, error) {
		return config.Control, nil
	}
	assembly, _, err := OpenProductionAssembly(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := assembly.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := connectorprotocol.ReadFrame(server); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	if err := assembly.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("shutdown waited for reconnect backoff: %s", elapsed)
	}
	if calls != 1 {
		t.Fatalf("reconnect provider called after cancellation: %d", calls)
	}
}

func TestProductionControlReconnectDelayIsBoundedAndConnectorScoped(t *testing.T) {
	for attempt := 1; attempt <= 64; attempt++ {
		delay := productionControlReconnectDelay(attempt, "connector-a")
		if delay <= 0 || delay > 5*time.Second {
			t.Fatalf("attempt %d delay=%s outside bounded range", attempt, delay)
		}
	}
	if productionControlReconnectDelay(3, "connector-a") == productionControlReconnectDelay(3, "connector-b") {
		t.Fatal("distinct connector identities must not share the same deterministic reconnect spread")
	}
}

func TestProductionAssemblyBootstrapsEmptyStoreBeforeCarrierActivation(t *testing.T) {
	config := newProductionAssemblyConfig(t)
	identity := config.SessionSource.Identity
	now := config.Clock.Now()
	config.Control.Hello.Auth.CredentialGeneration = 4
	config.InitialConnector.Credential.Generation = 4
	config.InitialConnector.RotationGeneration = 4
	carrierConfig := connector.DefaultDataCarrierConfig()
	config.SessionSource.Config = connector.DataCarrierPoolConfig{
		MaximumCarriers: 1,
		QueueDepth:      1,
		Preferred:       connector.TCPMux,
		Fallback:        connector.TCPMux,
		SingleTransport: true,
		EdgeID:          "edge-bootstrap-01",
		FailureDomains:  []string{"domain-bootstrap-01"},
		Carrier:         carrierConfig,
	}

	var identityMu sync.Mutex
	liveIdentity := identity
	config.SessionSource.IdentitySource = func(ctx context.Context) (connector.DataCarrierIdentity, error) {
		if ctx == nil {
			return connector.DataCarrierIdentity{}, ErrProductionAssemblyInvalid
		}
		identityMu.Lock()
		defer identityMu.Unlock()
		return liveIdentity, nil
	}
	config.ObserveWelcome = func(welcome connectorprotocol.Welcome) error {
		identityMu.Lock()
		liveIdentity.SessionID = welcome.SessionID
		identityMu.Unlock()
		return nil
	}

	var assembly *ProductionAssembly
	controlServer, controlClient := net.Pipe()
	defer controlServer.Close()
	var streamProviderCalls int
	config.ControlStream = func(ctx context.Context) (io.ReadWriteCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		streamProviderCalls++
		return controlClient, nil
	}
	config.ControlSessionFactory = func(context.Context, *CoordinatedConfigApplier) (connectorrotation.ControlSessionConfig, error) {
		return config.Control, nil
	}
	var carrierMu sync.Mutex
	var carriers []*connector.DataCarrier
	var dialCount int
	var stagedBeforeCarrier bool
	var stagedGenerations []uint64
	config.SessionSource.Dialer = func(ctx context.Context, request connector.DataCarrierDialRequest) (connector.DataCarrierDialResult, error) {
		if err := ctx.Err(); err != nil {
			return connector.DataCarrierDialResult{}, err
		}
		if assembly == nil {
			return connector.DataCarrierDialResult{}, ErrProductionAssemblyInvalid
		}
		state, _, err := assembly.Manager.config.Store.Snapshot()
		if err != nil {
			return connector.DataCarrierDialResult{}, err
		}
		carrierMu.Lock()
		if len(state.Tunnels) == 1 && len(state.Connectors) == 1 && state.Connectors[0].LastAppliedGeneration < state.Tunnels[0].DesiredGeneration {
			stagedBeforeCarrier = true
			stagedGenerations = append(stagedGenerations, state.Tunnels[0].DesiredGeneration)
		}
		dialCount++
		carrierMu.Unlock()
		local, remote := net.Pipe()
		server, err := connector.NewDataCarrierServer(context.Background(), remote, carrierConfig, connector.DataCarrierAdmission{
			Identity: request.Identity,
			Authorize: func(context.Context, connector.StreamOpen) error {
				return nil
			},
		})
		if err != nil {
			_ = local.Close()
			_ = remote.Close()
			return connector.DataCarrierDialResult{}, err
		}
		carrierMu.Lock()
		carriers = append(carriers, server)
		carrierMu.Unlock()
		return connector.DataCarrierDialResult{Link: local, PeerIdentity: request.Identity, Transport: request.Transport, EdgeID: request.EdgeID, FailureDomain: request.FailureDomain}, nil
	}
	lazySessionSource := config.SessionSource
	var descriptorCalls int
	config.CarrierDescriptorSource = func(ctx context.Context, welcome connectorprotocol.Welcome, request ApplyRequest) (connector.DataCarrierSessionSource, error) {
		if ctx == nil || welcome.SessionID == "" || request.Snapshot.Generation == 0 {
			return connector.DataCarrierSessionSource{}, ErrProductionAssemblyInvalid
		}
		carrierMu.Lock()
		descriptorCalls++
		carrierMu.Unlock()
		return lazySessionSource, nil
	}
	config.SessionSource = connector.DataCarrierSessionSource{}

	assembly, _, err := OpenProductionAssembly(config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = assembly.Shutdown(context.Background())
		carrierMu.Lock()
		for _, carrier := range carriers {
			_ = carrier.Close()
		}
		carrierMu.Unlock()
	}()
	if err := assembly.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	helloFrame, err := connectorprotocol.ReadFrame(controlServer)
	if err != nil {
		t.Fatalf("read bootstrap hello: %v", err)
	}
	if helloFrame.Type != connectorprotocol.MessageHello || helloFrame.RequestID != "hello-assembly-01" {
		t.Fatalf("bootstrap hello = %+v", helloFrame)
	}
	var hello connectorprotocol.Hello
	if err := helloFrame.DecodePayload(&hello); err != nil || hello.Auth.SignedProof == "" {
		t.Fatalf("bootstrap hello auth err=%v hello=%+v", err, hello)
	}
	welcome := connectorprotocol.Welcome{
		Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion, SessionID: "session-live-01",
		Capabilities:     config.Control.Hello.Capabilities,
		Lease:            connectorprotocol.Lease{SessionID: "session-live-01", ExpiresAt: now.Add(time.Minute), HeartbeatIntervalMS: 10000},
		RequiresSnapshot: true, ServerTime: now,
	}
	welcomeFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageWelcome, "welcome-bootstrap-01", welcome)
	if err != nil {
		t.Fatalf("welcome frame: %v", err)
	}
	if err := connectorprotocol.WriteFrame(controlServer, welcomeFrame); err != nil {
		t.Fatalf("write welcome: %v", err)
	}
	hostSnapshot := tunnelSnapshot(t, 1)
	snapshot, err := connectorprotocol.NewSnapshot(identity.TunnelID, 1, hostSnapshot.Payload)
	if err != nil {
		t.Fatalf("new snapshot: %v", err)
	}
	snapshot.AccountID = identity.AccountID
	snapshot.ConnectorID = identity.ConnectorID
	snapshot.SessionID = welcome.SessionID
	snapshot.ProcessGeneration = identity.ProcessGeneration
	snapshotFrame, err := connectorprotocol.NewFrame(connectorprotocol.MessageSnapshot, "snapshot-bootstrap-01", snapshot)
	if err != nil {
		t.Fatalf("snapshot frame: %v", err)
	}
	if err := connectorprotocol.WriteFrame(controlServer, snapshotFrame); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	if setter, ok := controlServer.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = setter.SetReadDeadline(time.Now().Add(5 * time.Second))
	}
	var ready connectorprotocol.Readiness
	for {
		frame, frameErr := connectorprotocol.ReadFrame(controlServer)
		if frameErr != nil {
			t.Fatalf("read bootstrap response: %v", frameErr)
		}
		switch frame.Type {
		case connectorprotocol.MessageAck:
			var ack connectorprotocol.Ack
			if err := frame.DecodePayload(&ack); err != nil {
				t.Fatalf("decode snapshot ack: %v", err)
			}
			if ack.Kind != connectorprotocol.AckSnapshot || ack.Status != connectorprotocol.AckApplied {
				t.Fatalf("snapshot ack = %+v", ack)
			}
		case connectorprotocol.MessageReady:
			if err := frame.DecodePayload(&ready); err != nil {
				t.Fatalf("decode ready: %v", err)
			}
		default:
			continue
		}
		if frame.Type == connectorprotocol.MessageReady {
			break
		}
	}
	if !ready.EdgeReady || !ready.RouteReady || !ready.OriginReady || ready.SessionID != welcome.SessionID || ready.Generation != snapshot.Generation || ready.ContentHash != snapshot.ContentHash {
		t.Fatalf("bootstrap readiness = %+v", ready)
	}
	carrierMu.Lock()
	firstDialCount := dialCount
	firstDescriptorCalls := descriptorCalls
	firstStagedBeforeCarrier := stagedBeforeCarrier
	firstStagedGenerations := append([]uint64(nil), stagedGenerations...)
	carrierMu.Unlock()
	if firstDialCount != 1 || firstDescriptorCalls != 1 || !firstStagedBeforeCarrier || len(firstStagedGenerations) != 1 || firstStagedGenerations[0] != 1 {
		t.Fatalf("bootstrap order descriptor_calls=%d dial_count=%d staged_before_carrier=%v staged_generations=%v", firstDescriptorCalls, firstDialCount, firstStagedBeforeCarrier, firstStagedGenerations)
	}
	carrierMu.Lock()
	if len(carriers) != 1 || carriers[0].ActiveStreams() != 0 {
		count := len(carriers)
		activeStreams := 0
		if count == 1 {
			activeStreams = carriers[0].ActiveStreams()
		}
		carrierMu.Unlock()
		t.Fatalf("bootstrap carrier state count=%d active_streams=%d; control must stay on bootstrap stream", count, activeStreams)
	}
	carrierMu.Unlock()
	state, revision, err := assembly.Manager.config.Store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Tunnels) != 1 || state.Tunnels[0].AppliedGeneration != 1 || state.Tunnels[0].LastKnownGood == nil || len(state.Connectors) != 1 || state.Connectors[0].LastAppliedGeneration != 1 {
		t.Fatalf("bootstrap durable state = %+v", state)
	}
	if got := assembly.ResourceCounts()["tunnels"]; got != 1 {
		t.Fatalf("active tunnel count = %d, want 1", got)
	}
	state.Connectors[0].Credential = hoststate.CredentialReference{Reference: "keychain://paperboat/connectors/connector_01", Generation: 5}
	state.Connectors[0].RotationGeneration = 5
	if _, err := assembly.Manager.config.Store.Commit(revision, state); err != nil {
		t.Fatalf("persist rotated connector fixture: %v", err)
	}
	identityMu.Lock()
	liveIdentity.Generation = 2
	identityMu.Unlock()
	hostSnapshot = tunnelSnapshot(t, 2)
	snapshot2, err := connectorprotocol.NewSnapshot(identity.TunnelID, 2, hostSnapshot.Payload)
	if err != nil {
		t.Fatalf("new second snapshot: %v", err)
	}
	snapshot2.AccountID = identity.AccountID
	snapshot2.ConnectorID = identity.ConnectorID
	snapshot2.SessionID = welcome.SessionID
	snapshot2.ProcessGeneration = identity.ProcessGeneration
	snapshotFrame2, err := connectorprotocol.NewFrame(connectorprotocol.MessageSnapshot, "snapshot-bootstrap-02", snapshot2)
	if err != nil {
		t.Fatalf("second snapshot frame: %v", err)
	}
	if err := connectorprotocol.WriteFrame(controlServer, snapshotFrame2); err != nil {
		t.Fatalf("write second snapshot: %v", err)
	}
	if setter, ok := controlServer.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = setter.SetReadDeadline(time.Now().Add(5 * time.Second))
	}
	var ready2 connectorprotocol.Readiness
	for {
		frame, frameErr := connectorprotocol.ReadFrame(controlServer)
		if frameErr != nil {
			t.Fatalf("read second bootstrap response: %v", frameErr)
		}
		switch frame.Type {
		case connectorprotocol.MessageAck:
			var ack connectorprotocol.Ack
			if err := frame.DecodePayload(&ack); err != nil {
				t.Fatalf("decode second snapshot ack: %v", err)
			}
			if ack.Kind != connectorprotocol.AckSnapshot || ack.Status != connectorprotocol.AckApplied || ack.Generation != 2 {
				t.Fatalf("second snapshot ack = %+v", ack)
			}
		case connectorprotocol.MessageReady:
			if err := frame.DecodePayload(&ready2); err != nil {
				t.Fatalf("decode second ready: %v", err)
			}
		}
		if frame.Type == connectorprotocol.MessageReady {
			break
		}
	}
	if !ready2.EdgeReady || !ready2.RouteReady || !ready2.OriginReady || ready2.Generation != 2 || ready2.ContentHash != snapshot2.ContentHash {
		t.Fatalf("second bootstrap readiness = %+v", ready2)
	}
	carrierMu.Lock()
	secondDialCount := dialCount
	secondStagedGenerations := append([]uint64(nil), stagedGenerations...)
	carrierMu.Unlock()
	if secondDialCount != 2 || len(secondStagedGenerations) != 2 || secondStagedGenerations[1] != 2 {
		t.Fatalf("second bootstrap order dial_count=%d staged_generations=%v", secondDialCount, secondStagedGenerations)
	}
	state, _, err = assembly.Manager.config.Store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if state.Connectors[0].Credential.Reference != "keychain://paperboat/connectors/connector_01" || state.Connectors[0].RotationGeneration != 5 || state.Connectors[0].Credential.Generation != 5 {
		t.Fatalf("later connector credential was overwritten: %+v", state.Connectors[0])
	}
	if err := assembly.Shutdown(context.Background()); err != nil {
		t.Fatalf("bootstrap shutdown: %v", err)
	}
	if streamProviderCalls != 1 {
		t.Fatalf("start must acquire exactly one bootstrap stream, calls=%d", streamProviderCalls)
	}
}
