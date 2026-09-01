package tunnelenrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connectorrotation"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelmanager"
)

type bootstrapClock struct{ now time.Time }

func (c bootstrapClock) Now() time.Time { return c.now }

type bootstrapOrigins struct{}

func (bootstrapOrigins) ProbeOrigin(context.Context, hoststate.TunnelConfigRoute) error { return nil }

type bootstrapDrainer struct{}

func (bootstrapDrainer) StopNewStreams(context.Context) error          { return nil }
func (bootstrapDrainer) ActiveStreams(context.Context) (uint32, error) { return 0, nil }
func (bootstrapDrainer) ForceClose(context.Context) error              { return nil }

type bootstrapMachineAuth struct {
	mu        sync.Mutex
	operation string
	method    string
	path      string
	body      []byte
}

func (*bootstrapMachineAuth) Token(context.Context) (string, error) {
	return strings.Repeat("i", 48), nil
}
func (a *bootstrapMachineAuth) Proof(_ context.Context, operation, method, path string, body []byte) ([]byte, error) {
	a.mu.Lock()
	a.operation, a.method, a.path, a.body = operation, method, path, append([]byte(nil), body...)
	a.mu.Unlock()
	digest := sha256.Sum256(append([]byte(operation+method+path), body...))
	return digest[:], nil
}

func TestHTTPSProductionAssemblySourceControlUsesOnlySignedHelloWebSocket(t *testing.T) {
	now := time.Now().UTC()
	request, private := productionActivationRequest(t)
	helloRead := make(chan connectorprotocol.Hello, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/tunnels/tunnel_01/connectors/connector_01/control" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Errorf("unsafe control request path=%q query=%q auth=%q cookie=%q", r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), r.Header.Get("Cookie"))
		}
		connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{controlSubprotocol}, CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer connection.Close(websocket.StatusNormalClosure, "done")
		stream := websocket.NetConn(r.Context(), connection, websocket.MessageBinary)
		defer stream.Close()
		frame, err := connectorprotocol.ReadFrame(stream)
		if err != nil {
			t.Errorf("read hello: %v", err)
			return
		}
		var hello connectorprotocol.Hello
		if frame.Type != connectorprotocol.MessageHello || frame.DecodePayload(&hello) != nil {
			t.Errorf("frame = %+v", frame)
			return
		}
		helloRead <- hello
	}))
	defer server.Close()
	auth := &bootstrapMachineAuth{}
	source := newBootstrapSourceForTest(t, server, now, auth)
	identity := ControlIdentity{AccountID: "account_01", ProcessGeneration: 2, CredentialGeneration: 3}
	hello, err := source.newHello(context.Background(), request, identity, func(_ context.Context, payload []byte) ([]byte, error) { return ed25519.Sign(private, payload), nil })
	if err != nil {
		t.Fatal(err)
	}
	stream, err := source.openControlStream(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	frame, _ := connectorprotocol.NewFrame(connectorprotocol.MessageHello, "operation_01", hello)
	if err := connectorprotocol.WriteFrame(stream, frame); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-helloRead:
		if got.Auth.CredentialGeneration != 3 || got.ProcessGeneration != 2 || got.Auth.SignedProof == "" {
			t.Fatalf("hello = %+v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive signed Hello")
	}
}

func TestHTTPSProductionAssemblySourceBootstrapBindsProofDescriptorAndLazySession(t *testing.T) {
	now := time.Now().UTC()
	request, private := productionActivationRequest(t)
	var descriptor carrierBootstrapDescriptor
	auth := &bootstrapMachineAuth{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/tunnels/tunnel_01/connectors/connector_01/carrier-bootstrap" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Paperboat-Machine-Identity") != strings.Repeat("i", 48) || r.Header.Get("X-Paperboat-Machine-Proof") == "" || r.Header.Get("Idempotency-Key") == "" {
			t.Errorf("bootstrap request headers/path are not machine-proof-only")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": descriptor})
	}))
	defer server.Close()
	chainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	spki := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	descriptor = carrierBootstrapDescriptor{
		Schema: carrierBootstrapSchema, Kind: "carrier_bootstrap_descriptor",
		AccountID: "account_01", TunnelID: request.TunnelID, ConnectorID: request.ConnectorID, HostID: request.HostID,
		StableEndpointID: request.StableEndpointID,
		SessionID:        "session_live_01", ProcessGeneration: 2, CredentialGeneration: 3,
		ConfigGeneration: 7, ConfigContentHash: "sha256:" + strings.Repeat("a", 64),
		Carriers: []carrierBootstrapNode{{EdgeNodeID: "edge_01", EdgeProcessEpoch: "epoch_0001", FailureDomain: "zone_a", Endpoints: []string{"tls://127.0.0.1:4443", "quic://127.0.0.1:4444"}, ServerSPKISHA256: "sha256:" + hex.EncodeToString(spki[:]), ServerCertificateChainPEM: string(chainPEM)}},
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	source := newBootstrapSourceForTest(t, server, now, auth)
	identity := ControlIdentity{AccountID: "account_01", ProcessGeneration: 2, CredentialGeneration: 3}
	hello := connectorprotocol.Hello{AccountID: identity.AccountID, TunnelID: request.TunnelID, ConnectorID: request.ConnectorID, HostID: request.HostID, ProcessGeneration: identity.ProcessGeneration}
	welcome := connectorprotocol.Welcome{SessionID: descriptor.SessionID}
	apply := tunnelmanager.ApplyRequest{Snapshot: hoststate.ConfigSnapshot{Generation: descriptor.ConfigGeneration, ContentHash: descriptor.ConfigContentHash}}
	sessionSource, err := source.carrierSessionSource(context.Background(), request, identity, hello, welcome, apply, func(_ context.Context, payload []byte) ([]byte, error) { return ed25519.Sign(private, payload), nil })
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := sessionSource.PrepareDataCarrier(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Identity.AccountID != descriptor.AccountID || prepared.Identity.SessionID != descriptor.SessionID || prepared.Identity.Generation != descriptor.ConfigGeneration || prepared.Config.MaximumCarriers != 1 || prepared.Config.FailureDomains[0] != "zone_a" {
		t.Fatalf("prepared carrier = %+v config=%+v", prepared.Identity, prepared.Config)
	}
	auth.mu.Lock()
	defer auth.mu.Unlock()
	if auth.operation == "" || auth.method != http.MethodPost || auth.path != rpath(request) || len(auth.body) == 0 {
		t.Fatalf("proof = operation %q method %q path %q body %q", auth.operation, auth.method, auth.path, auth.body)
	}
	var bootstrap carrierBootstrapRequest
	if json.Unmarshal(auth.body, &bootstrap) != nil || bootstrap.SessionID != descriptor.SessionID || bootstrap.ProcessGeneration != descriptor.ProcessGeneration || bootstrap.ConfigGeneration != descriptor.ConfigGeneration || bootstrap.ConfigContentHash != descriptor.ConfigContentHash {
		t.Fatalf("bootstrap proof body = %+v", bootstrap)
	}
}

func TestCarrierBootstrapDescriptorRequiresExactStableEndpointUUID(t *testing.T) {
	request, _ := productionActivationRequest(t)
	identity := ControlIdentity{AccountID: request.AccountID, ProcessGeneration: request.ProcessGeneration, CredentialGeneration: request.CredentialGeneration}
	base := carrierBootstrapDescriptor{
		Schema: carrierBootstrapSchema, Kind: "carrier_bootstrap_descriptor",
		AccountID: request.AccountID, TunnelID: request.TunnelID, ConnectorID: request.ConnectorID, HostID: request.HostID,
		StableEndpointID: request.StableEndpointID, SessionID: "session_live_01",
		ProcessGeneration: request.ProcessGeneration, CredentialGeneration: request.CredentialGeneration,
		ConfigGeneration: 7, ConfigContentHash: "sha256:" + strings.Repeat("a", 64),
		IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute),
	}
	welcome := connectorprotocol.Welcome{SessionID: base.SessionID}
	apply := tunnelmanager.ApplyRequest{Snapshot: hoststate.ConfigSnapshot{Generation: base.ConfigGeneration, ContentHash: base.ConfigContentHash}}
	for _, test := range []struct {
		name string
		id   string
	}{
		{name: "missing", id: ""},
		{name: "malformed", id: "endpoint_01"},
		{name: "mismatched", id: "123e4567-e89b-12d3-a456-426614174001"},
	} {
		t.Run(test.name, func(t *testing.T) {
			descriptor := base
			descriptor.StableEndpointID = test.id
			if err := validateCarrierDescriptor(descriptor, time.Now().UTC(), request, identity, welcome, apply); !errors.Is(err, ErrConflict) {
				t.Fatalf("stable endpoint id %q error = %v, want conflict", test.id, err)
			}
		})
	}
	changed := request
	changed.StableEndpointID = "123e4567-e89b-12d3-a456-426614174001"
	if sameActivation(request, changed) {
		t.Fatal("stable endpoint replacement was treated as the same activation")
	}
}

func TestReplacementControlUsesPriorRotationJournalThenRejoinsNextGeneration(t *testing.T) {
	now := time.Now().UTC()
	request, _ := productionActivationRequest(t)
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	source := newBootstrapSourceForTest(t, server, now, &bootstrapMachineAuth{})
	store, err := NewFileCredentialStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := source.BindCredentialStore(store); err != nil {
		t.Fatal(err)
	}
	if err := source.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer source.Shutdown(context.Background())
	prior, err := source.rotationFor(request)
	if err != nil {
		t.Fatal(err)
	}
	newPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newThumbprint, err := connectorprotocol.IdentityThumbprint(newPublic)
	if err != nil {
		t.Fatal(err)
	}
	next := request
	next.OperationID = "operation_rotation_01"
	next.CredentialReference = "protected-file://paperboat/connectors/credential_02"
	next.CredentialKeyID = "ed25519:" + newThumbprint
	next.CredentialThumbprint = newThumbprint
	next.CredentialPublicKey = append([]byte(nil), newPublic...)
	next.CredentialGeneration++
	next.ProcessGeneration++
	signer := func(context.Context, []byte) ([]byte, error) { return make([]byte, ed25519.SignatureSize), nil }
	config, err := source.resolveProductionAssembly(context.Background(), next, signer, prior)
	if err != nil {
		t.Fatal(err)
	}
	if config.StableEndpointID != next.StableEndpointID {
		t.Fatalf("production config stable endpoint id = %q, want %q", config.StableEndpointID, next.StableEndpointID)
	}
	if config.Control.Rotation != prior.manager {
		t.Fatal("replacement session did not retain the prior rotation journal through revoke")
	}
	prior.mu.Lock()
	prior.revokeCommitted = true
	prior.mu.Unlock()
	rejoined, err := config.ControlSessionFactory(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rejoined.Rotation == prior.manager || rejoined.Rotation == nil {
		t.Fatal("post-revoke reconnect did not select the new credential journal")
	}
}

func newBootstrapSourceForTest(t *testing.T, server *httptest.Server, now time.Time, auth MachineAuth) *HTTPSProductionAssemblySource {
	t.Helper()
	source, err := NewHTTPSProductionAssemblySource(HTTPSProductionAssemblySourceConfig{
		ControlURL: server.URL, StateRoot: t.TempDir(), HostID: "host_01", Transport: server.Client().Transport,
		Auth:  auth,
		Clock: bootstrapClock{now: now}, Origins: bootstrapOrigins{}, Drainer: bootstrapDrainer{},
		Renewal: connectorrotation.CredentialRenewalSourceFunc(func(context.Context, time.Time) (string, string, error) {
			return "renewal_nonce_01", "renewal_proof_01", nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func productionActivationRequest(t *testing.T) (ActivationRequest, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := connectorprotocol.IdentityThumbprint(public)
	if err != nil {
		t.Fatal(err)
	}
	return ActivationRequest{
		AccountID: "account_01", TunnelID: "tunnel_01", HostID: "host_01", ConnectorID: "connector_01", OperationID: "operation_01",
		StableEndpointID:    "123e4567-e89b-12d3-a456-426614174000",
		CredentialReference: "protected-file://paperboat/connectors/credential_01", CredentialKeyID: "ed25519:" + thumbprint,
		CredentialThumbprint: thumbprint, CredentialPublicKey: append([]byte(nil), public...), CredentialGeneration: 3, ProcessGeneration: 2,
	}, private
}

func rpath(request ActivationRequest) string {
	return "/v1/tunnels/" + request.TunnelID + "/connectors/" + request.ConnectorID + "/carrier-bootstrap"
}
