package tunnelenrollment

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelmanager"
)

type rotationRuntimeActive struct {
	carrier               *connector.ActiveDataCarrier
	tunnelID, connectorID string
	generation            uint64
	hash                  string
}

func (a *rotationRuntimeActive) TunnelID() string                                { return a.tunnelID }
func (a *rotationRuntimeActive) ConnectorID() string                             { return a.connectorID }
func (a *rotationRuntimeActive) Generation() uint64                              { return a.generation }
func (a *rotationRuntimeActive) ContentHash() string                             { return a.hash }
func (a *rotationRuntimeActive) ActiveDataCarrier() *connector.ActiveDataCarrier { return a.carrier }
func (a *rotationRuntimeActive) Drain(ctx context.Context) error                 { return a.carrier.Drain(ctx) }
func (a *rotationRuntimeActive) Close(ctx context.Context) error                 { return a.carrier.Close(ctx) }

func TestProductionRotationRuntimeDrainsPromotesAndShutsOnlyOldAssembly(t *testing.T) {
	now := time.Now().UTC()
	store, previous, next := rotationPromotionFixture(t, now)
	active, edge, accepted := rotationRuntimeCarrier(t, previous)
	defer edge.Close()
	existing, err := active.carrier.OpenStream(context.Background(), rotationRuntimeOpen(previous, "request-existing"))
	if err != nil {
		t.Fatal(err)
	}
	edgeExisting := <-accepted
	oldAssembly, replacementAssembly := &tunnelmanager.ProductionAssembly{}, &tunnelmanager.ProductionAssembly{}
	runtime := &productionRotationRuntime{
		source: &HTTPSProductionAssemblySource{clock: bootstrapClock{now: now}, credentials: store}, request: previous,
		keys:    &rotationCredentialStore{store: store, oldReference: previous.CredentialReference},
		install: &connectorprotocol.CredentialRotationInstall{OperationID: next.OperationID}, replacementReq: next,
		current: oldAssembly, replacement: replacementAssembly,
		replacementID: func(*tunnelmanager.ProductionAssembly) (string, bool) { return "session_replacement_01", true },
		oldCarrier: func(got *tunnelmanager.ProductionAssembly) (tunnelmanager.Active, *connector.ActiveDataCarrier, error) {
			if got != oldAssembly {
				return nil, nil, ErrConflict
			}
			return active, active.carrier, nil
		},
	}
	var shutdownAssembly *tunnelmanager.ProductionAssembly
	runtime.shutdownOld = func(_ context.Context, assembly *tunnelmanager.ProductionAssembly) error {
		shutdownAssembly = assembly
		return active.carrier.Close(context.Background())
	}
	revoke := rotationRuntimeRevoke(previous, next, now)
	if err := runtime.Revoke(context.Background(), revoke); err != nil {
		t.Fatal(err)
	}
	if _, err := active.carrier.OpenStream(context.Background(), rotationRuntimeOpen(previous, "request-rejected")); !errors.Is(err, connector.ErrDataCarrierDraining) {
		t.Fatalf("new stream after revoke=%v", err)
	}
	if _, err := existing.Write([]byte("existing-survives")); err != nil {
		t.Fatalf("existing stream was cut before commit: %v", err)
	}
	if err := runtime.keys.Delete(context.Background(), previous.CredentialReference); err != nil {
		t.Fatal(err)
	}
	store.failSave = 1
	if err := runtime.PrepareRevoke(context.Background(), revoke); !errors.Is(err, ErrSecretStore) {
		t.Fatalf("promotion failure=%v", err)
	}
	unchanged, _ := store.loadJournal()
	if got := unchanged.Records[previous.TunnelID]; got.Credential.Reference != previous.CredentialReference || got.ProcessGeneration != previous.ProcessGeneration {
		t.Fatalf("failed promotion changed restart journal=%+v", got)
	}
	if _, err := store.Sign(context.Background(), previous.CredentialReference, []byte("still-usable")); err != nil {
		t.Fatalf("promotion failure deleted old key: %v", err)
	}
	if err := runtime.PrepareRevoke(context.Background(), revoke); err != nil {
		t.Fatal(err)
	}
	promoted, _ := store.loadJournal()
	if got := promoted.Records[previous.TunnelID]; got.Credential.Reference != next.CredentialReference || got.ProcessGeneration != next.ProcessGeneration {
		t.Fatalf("pre-ack journal not promoted=%+v", got)
	}
	if _, err := store.Sign(context.Background(), previous.CredentialReference, []byte("revoked")); !errors.Is(err, ErrSecretStore) {
		t.Fatalf("old key survived committed promotion: %v", err)
	}
	// Simulate an ACK write crash: no CommitRevoke has run, but a fresh hostd
	// must already select the new credential from the durable journal.
	rejoined := &testActivator{}
	manager, err := NewManager(ManagerConfig{ControlURL: "https://api.example.test", HostID: previous.HostID, Auth: &testAuth{}, Credentials: store, Activator: rejoined, ControlToken: "local-token"})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rejoined.input.CredentialReference != next.CredentialReference || rejoined.input.ProcessGeneration != next.ProcessGeneration+1 {
		t.Fatalf("restart selected=%+v", rejoined.input)
	}
	if shutdownAssembly != nil {
		t.Fatal("old assembly shut down before terminal ACK")
	}
	if _, err := existing.Write([]byte("still-overlap")); err != nil {
		t.Fatalf("existing stream did not survive pre-ack: %v", err)
	}
	_ = existing.Close()
	_ = edgeExisting.Close()
	if err := runtime.CommitRevoke(context.Background(), revoke); err != nil {
		t.Fatal(err)
	}
	if shutdownAssembly != oldAssembly {
		t.Fatalf("shutdown assembly=%p want old=%p", shutdownAssembly, oldAssembly)
	}
	if runtime.current != replacementAssembly {
		t.Fatal("replacement assembly was not retained")
	}
}

func rotationPromotionFixture(t *testing.T, now time.Time) (*FileCredentialStore, ActivationRequest, ActivationRequest) {
	t.Helper()
	store, err := NewFileCredentialStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	oldCredential, err := store.CreateKey(context.Background(), "runtime-old")
	if err != nil {
		t.Fatal(err)
	}
	previous := ActivationRequest{AccountID: "account_01", TunnelID: "tunnel_01", HostID: "host_01", ConnectorID: "connector_01", OperationID: "operation_enroll_01", StableEndpointID: "123e4567-e89b-12d3-a456-426614174000", CredentialReference: oldCredential.Reference, CredentialKeyID: oldCredential.KeyID, CredentialThumbprint: oldCredential.Thumbprint, CredentialPublicKey: oldCredential.PublicKey, CredentialGeneration: 3, ProcessGeneration: 7}
	readyAt := now
	projection := Projection{Schema: Schema, Kind: "tunnel_connector", TunnelID: previous.TunnelID, HostID: previous.HostID, ConnectorID: previous.ConnectorID, OperationID: previous.OperationID, State: "ready", CredentialReference: previous.CredentialReference, CredentialGeneration: previous.CredentialGeneration, ReadyAt: &readyAt}
	state := journal{Version: 1, Records: map[string]record{previous.TunnelID: {AccountID: previous.AccountID, TunnelID: previous.TunnelID, HostID: previous.HostID, LocalKey: "local-runtime-01", IssueKey: "issue-runtime-01", ExchangeKey: "exchange-runtime-01", Credential: oldCredential, EnrollmentID: "enrollment_runtime_01", TokenReference: "token-enrollment_runtime_01", ConnectorID: previous.ConnectorID, OperationID: previous.OperationID, StableEndpointID: previous.StableEndpointID, CredentialGeneration: previous.CredentialGeneration, ProcessGeneration: previous.ProcessGeneration, Phase: "active", Projection: &projection}}}
	if err := store.saveJournal(state); err != nil {
		t.Fatal(err)
	}
	newCredential, err := store.CreateKey(context.Background(), "runtime-new")
	if err != nil {
		t.Fatal(err)
	}
	next := previous
	next.OperationID = "operation_rotation_01"
	next.CredentialReference = newCredential.Reference
	next.CredentialKeyID = newCredential.KeyID
	next.CredentialThumbprint = newCredential.Thumbprint
	next.CredentialPublicKey = newCredential.PublicKey
	next.CredentialGeneration++
	next.ProcessGeneration++
	return store, previous, next
}

func rotationRuntimeCarrier(t *testing.T, request ActivationRequest) (*rotationRuntimeActive, *connector.DataCarrier, <-chan io.ReadWriteCloser) {
	t.Helper()
	identity := connector.DataCarrierIdentity{AccountID: request.AccountID, HostID: request.HostID, TunnelID: request.TunnelID, ConnectorID: request.ConnectorID, SessionID: "session_old_01", ProcessGeneration: request.ProcessGeneration, Generation: 1}
	config := connector.DefaultDataCarrierPoolConfig()
	config.MaximumCarriers = 1
	config.SingleTransport = true
	config.Preferred = connector.QUIC
	config.Fallback = connector.QUIC
	config.EdgeID = "edge_01"
	config.FailureDomains = []string{"zone_a"}
	config.Session = identity
	accepted := make(chan io.ReadWriteCloser, 1)
	var edge *connector.DataCarrier
	prepared, err := connector.PrepareDataCarrier(context.Background(), identity, config, func(_ context.Context, dial connector.DataCarrierDialRequest) (connector.DataCarrierDialResult, error) {
		local, remote := net.Pipe()
		var openErr error
		edge, openErr = connector.NewDataCarrierServer(context.Background(), remote, config.Carrier, connector.DataCarrierAdmission{Identity: identity, Authorize: func(context.Context, connector.StreamOpen) error { return nil }})
		if openErr != nil {
			return connector.DataCarrierDialResult{}, openErr
		}
		go func() {
			stream, _, acceptErr := edge.AcceptStream(context.Background())
			if acceptErr == nil {
				accepted <- stream
			}
		}()
		return connector.DataCarrierDialResult{Link: local, PeerIdentity: identity, Transport: dial.Transport, EdgeID: dial.EdgeID, FailureDomain: dial.FailureDomain}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	active, err := prepared.Activate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return &rotationRuntimeActive{carrier: active, tunnelID: request.TunnelID, connectorID: request.ConnectorID, generation: 1, hash: "sha256:" + strings.Repeat("b", 64)}, edge, accepted
}

func rotationRuntimeOpen(request ActivationRequest, requestID string) connector.StreamOpen {
	return connector.StreamOpen{Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion, AccountID: request.AccountID, TunnelID: request.TunnelID, ConnectorID: request.ConnectorID, SessionID: "session_old_01", ProcessGeneration: request.ProcessGeneration, Generation: 1, RouteID: "route_01", RequestID: requestID, Kind: "http"}
}

func rotationRuntimeRevoke(previous, next ActivationRequest, now time.Time) connectorprotocol.CredentialRotationRevoke {
	return connectorprotocol.CredentialRotationRevoke{AccountID: previous.AccountID, TunnelID: previous.TunnelID, OperationID: next.OperationID, ConnectorID: previous.ConnectorID, HostID: previous.HostID, SessionID: "session_replacement_01", ProcessGeneration: next.ProcessGeneration, TargetSetHash: "sha256:" + strings.Repeat("a", 64), OldCredentialGeneration: previous.CredentialGeneration, NewCredentialGeneration: next.CredentialGeneration, RevokeNonce: "rotation-revoke-runtime-01", IssuedAt: now, Deadline: now.Add(connectorprotocol.DefaultAbortTimeout)}
}
