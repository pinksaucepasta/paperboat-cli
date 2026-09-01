package preview

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
)

func TestMachineAttachmentSessionSourceSharesAndReleasesMachineCarrier(t *testing.T) {
	ctx := context.Background()
	stateRoot, store := newMachineAttachmentIdentity(t)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	identityValue := testPreviewCarrierIdentity(1)
	admission := machineAttachmentAdmission(t, store, now, identityValue, []string{"tls://edge.example.test:8443", "quic://edge.example.test:9443"})

	var mu sync.Mutex
	var calls int
	var endpointConfig connector.NetworkDialerConfig
	var poolConfig connector.DataCarrierPoolConfig
	var edges []*connector.DataCarrier
	factory := func(got connector.DataCarrierIdentity, config connector.DataCarrierPoolConfig, endpoints connector.NetworkDialerConfig) (connector.DataCarrierSessionSource, error) {
		mu.Lock()
		calls++
		endpointConfig, poolConfig = endpoints, config
		mu.Unlock()
		local, remote := net.Pipe()
		edge, err := connector.NewDataCarrierServer(ctx, remote, config.Carrier, connector.DataCarrierAdmission{Identity: got, Authorize: func(context.Context, connector.StreamOpen) error { return nil }})
		if err != nil {
			_ = local.Close()
			_ = remote.Close()
			return connector.DataCarrierSessionSource{}, err
		}
		mu.Lock()
		edges = append(edges, edge)
		mu.Unlock()
		dialer := connector.DataCarrierDialer(func(_ context.Context, request connector.DataCarrierDialRequest) (connector.DataCarrierDialResult, error) {
			return connector.DataCarrierDialResult{Link: local, PeerIdentity: got, Transport: request.Transport, EdgeID: request.EdgeID, FailureDomain: request.FailureDomain}, nil
		})
		return connector.NewDataCarrierSessionSource(got, config, dialer)
	}
	source, err := NewMachineAttachmentSessionSource(MachineAttachmentSessionSourceConfig{StateRoot: stateRoot, Clock: func() time.Time { return now }, SessionFactory: factory})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = source.Close(context.Background())
		mu.Lock()
		defer mu.Unlock()
		for _, edge := range edges {
			_ = edge.Close()
		}
	})

	first, err := source.AcquirePreviewDataCarrier(ctx, admission)
	if err != nil {
		t.Fatal(err)
	}
	second, err := source.AcquirePreviewDataCarrier(ctx, admission)
	if err != nil {
		t.Fatal(err)
	}
	if first.Active != second.Active || first.Identity != second.Identity {
		t.Fatal("two routes did not share the authenticated machine carrier")
	}
	mu.Lock()
	if calls != 1 {
		t.Fatalf("session factory calls = %d, want 1", calls)
	}
	capturedEndpoint, capturedPool := endpointConfig, poolConfig
	mu.Unlock()
	if capturedPool.MaximumCarriers != 1 || capturedPool.Preferred != connector.QUIC || capturedPool.Fallback != connector.TCPMux || capturedPool.SingleTransport {
		t.Fatalf("pool config = %+v", capturedPool)
	}
	if capturedPool.EdgeID != admission.Binding.EdgeNodeID || len(capturedPool.FailureDomains) != 1 || capturedPool.FailureDomains[0] != admission.Binding.EdgeNodeID {
		t.Fatalf("pool binding = %+v", capturedPool)
	}
	if capturedEndpoint.QUIC.Address != "edge.example.test:9443" || capturedEndpoint.TCPMux.Address != "edge.example.test:8443" {
		t.Fatalf("endpoint addresses = TCP %q QUIC %q", capturedEndpoint.TCPMux.Address, capturedEndpoint.QUIC.Address)
	}
	for name, endpoint := range map[string]connector.DataCarrierEndpointConfig{"tcp": capturedEndpoint.TCPMux, "quic": capturedEndpoint.QUIC} {
		if endpoint.TLS == nil || endpoint.TLS.MinVersion != tls.VersionTLS13 || endpoint.TLS.MaxVersion != tls.VersionTLS13 || endpoint.TLS.InsecureSkipVerify || endpoint.TLS.ServerName != "edge.example.test" || len(endpoint.TLS.Certificates) != 1 {
			t.Fatalf("%s TLS config = %#v", name, endpoint.TLS)
		}
		if endpoint.TLS.Certificates[0].Leaf == nil || endpoint.TLS.Certificates[0].Leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
			t.Fatalf("%s TLS leaf = %#v", name, endpoint.TLS.Certificates[0].Leaf)
		}
		wantURN, err := connectorprotocol.CarrierIdentityURN(connectorprotocol.CarrierIdentityBinding{
			AccountID: identityValue.AccountID, HostID: identityValue.HostID, TunnelID: identityValue.TunnelID,
			ConnectorID: identityValue.ConnectorID, SessionID: identityValue.SessionID,
			ProcessGeneration: identityValue.ProcessGeneration, ConfigGeneration: identityValue.Generation,
			EdgeProcessEpoch: admission.Binding.EdgeProcessEpoch,
		})
		if err != nil || len(endpoint.TLS.Certificates[0].Leaf.URIs) != 1 || endpoint.TLS.Certificates[0].Leaf.URIs[0].String() != wantURN.String() {
			t.Fatalf("%s TLS carrier URI SAN = %v, want %v (err=%v)", name, endpoint.TLS.Certificates[0].Leaf.URIs, wantURN, err)
		}
		peer := firstCertificateFromPEM(t, admission.Binding.EdgeCarrierServerCertificateChainPEM)
		bound, err := endpoint.PeerBinding(tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{peer}}, PeerCertificates: []*x509.Certificate{peer}})
		if err != nil || bound != identityValue {
			t.Fatalf("%s peer binding = %+v, err=%v", name, bound, err)
		}
		if _, err := endpoint.PeerBinding(tls.ConnectionState{}); !errors.Is(err, ErrMachineAttachmentTrustRequired) {
			t.Fatalf("%s empty verified chain err=%v", name, err)
		}
	}

	if err := first.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if first.Active.Pool().State() != connector.DataCarrierPoolReady {
		t.Fatal("first release closed a carrier still owned by a sibling route")
	}
	if err := first.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if err := second.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if second.Active.Pool().State() != connector.DataCarrierPoolClosed {
		t.Fatalf("carrier state after final release = %s", second.Active.Pool().State())
	}
	if err := second.Release(ctx); err != nil {
		t.Fatalf("idempotent release = %v", err)
	}

	third, err := source.AcquirePreviewDataCarrier(ctx, admission)
	if err != nil {
		t.Fatal(err)
	}
	if third.Active == first.Active {
		t.Fatal("released carrier was retained in source cache")
	}
	mu.Lock()
	if calls != 2 {
		t.Fatalf("session factory calls after reuse = %d, want 2", calls)
	}
	mu.Unlock()
	if err := third.Release(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestMachineAttachmentSessionSourceRejectsMachineAndEndpointMismatch(t *testing.T) {
	stateRoot, store := newMachineAttachmentIdentity(t)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	identityValue := testPreviewCarrierIdentity(1)
	valid := machineAttachmentAdmission(t, store, now, identityValue, []string{"tls://edge.example.test"})
	source, err := NewMachineAttachmentSessionSource(MachineAttachmentSessionSourceConfig{
		StateRoot: stateRoot,
		Clock:     func() time.Time { return now },
		SessionFactory: func(connector.DataCarrierIdentity, connector.DataCarrierPoolConfig, connector.NetworkDialerConfig) (connector.DataCarrierSessionSource, error) {
			t.Fatal("session factory called for invalid admission")
			return connector.DataCarrierSessionSource{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	badMachine := valid
	badMachine.Binding.MachineIdentityPublicKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x99}, ed25519.PublicKeySize))
	if _, err := source.AcquirePreviewDataCarrier(context.Background(), badMachine); !errors.Is(err, ErrMachineAttachmentSessionInvalid) {
		t.Fatalf("machine mismatch err=%v", err)
	}
	badEndpoint := valid
	badEndpoint.EdgeEndpoints = []string{"https://edge.example.test"}
	if _, err := source.AcquirePreviewDataCarrier(context.Background(), badEndpoint); !errors.Is(err, ErrMachineAttachmentSessionInvalid) {
		t.Fatalf("endpoint mismatch err=%v", err)
	}
}

func TestMachineAttachmentSessionSourceRequiresPinnedTrustAndExactEdgeTuple(t *testing.T) {
	stateRoot, store := newMachineAttachmentIdentity(t)
	now := time.Now().UTC()
	identityValue := testPreviewCarrierIdentity(1)
	admission := machineAttachmentAdmission(t, store, now, identityValue, []string{"tls://edge.example.test"})
	base := MachineAttachmentSessionSourceConfig{StateRoot: stateRoot, Clock: func() time.Time { return now }}
	source, err := NewMachineAttachmentSessionSource(base)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := store.CurrentTLSCertificate(now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	endpoints, _, _, err := source.endpointConfigs(admission, identityValue, leaf)
	if err != nil {
		t.Fatal(err)
	}
	peer := firstCertificateFromPEM(t, admission.Binding.EdgeCarrierServerCertificateChainPEM)
	state := tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{peer}}, PeerCertificates: []*x509.Certificate{peer}}
	if _, err := endpoints.TCPMux.PeerBinding(state); err != nil {
		t.Fatalf("exact edge tuple rejected: %v", err)
	}
	stale := admission
	stale.Binding.EdgeProcessEpoch = "edge_epoch_02"
	_, staleCertificate := testEdgeServerCertificate(t, now, identityValue, stale.Binding.EdgeProcessEpoch)
	stale.Binding.EdgeCarrierServerSPKISHA256, stale.Binding.EdgeCarrierServerCertificateChainPEM = testEdgeServerTrust(t, staleCertificate)
	staleEndpoints, _, _, err := source.endpointConfigs(stale, identityValue, leaf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staleEndpoints.TCPMux.PeerBinding(state); err == nil {
		t.Fatal("stale edge process epoch was accepted")
	}
}

func TestNormalizeCarrierEndpointIsStrictAndUsesTLSDefaultPort(t *testing.T) {
	tests := []struct {
		name, value, scheme, address, serverName string
	}{
		{name: "tls", value: "tls://edge.example.test", scheme: "tls", address: "edge.example.test:443", serverName: "edge.example.test"},
		{name: "tls-explicit", value: "tls://edge.example.test:9443/", scheme: "tls", address: "edge.example.test:9443", serverName: "edge.example.test"},
		{name: "quic", value: "quic://[::1]:7443", scheme: "quic", address: "[::1]:7443", serverName: "::1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scheme, address, serverName, err := normalizeCarrierEndpoint(test.value)
			if err != nil || scheme != test.scheme || address != test.address || serverName != test.serverName {
				t.Fatalf("normalized = %q %q %q, err=%v", scheme, address, serverName, err)
			}
		})
	}
	for _, value := range []string{
		"http://edge.example.test",
		"https://edge.example.test",
		"wss://edge.example.test",
		"tls://user:secret@edge.example.test",
		"tls://edge.example.test/carrier",
		"tls://edge.example.test?token=secret",
		"tls://edge.example.test:bad",
	} {
		if _, _, _, err := normalizeCarrierEndpoint(value); !errors.Is(err, ErrMachineAttachmentSessionInvalid) {
			t.Fatalf("%q error = %v", value, err)
		}
	}
}

func TestMachineAttachmentSessionSourceUsesStandardTLSHostnameAndRoots(t *testing.T) {
	stateRoot, store := newMachineAttachmentIdentity(t)
	now := time.Now().UTC().Truncate(time.Second)
	identityValue := testPreviewCarrierIdentity(1)
	_, serverCertificate := testEdgeServerCertificate(t, now, identityValue, "edge_epoch_01")
	source, err := NewMachineAttachmentSessionSource(MachineAttachmentSessionSourceConfig{StateRoot: stateRoot, Clock: func() time.Time { return now }, SessionFactory: func(connector.DataCarrierIdentity, connector.DataCarrierPoolConfig, connector.NetworkDialerConfig) (connector.DataCarrierSessionSource, error) {
		return connector.DataCarrierSessionSource{}, errors.New("not used")
	}})
	if err != nil {
		t.Fatal(err)
	}
	admission := machineAttachmentAdmission(t, store, now, identityValue, []string{"tls://edge.example.test"})
	admission.Binding.EdgeCarrierServerSPKISHA256, admission.Binding.EdgeCarrierServerCertificateChainPEM = testEdgeServerTrust(t, serverCertificate)
	key := store.Current()
	leaf, err := store.CurrentTLSCertificate(now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	endpoints, _, _, err := source.endpointConfigs(admission, identityValue, leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := handshakeWithServer(endpoints.TCPMux.TLS, serverCertificate); err != nil {
		t.Fatalf("trusted endpoint handshake: %v", err)
	}
	wrongHost := endpoints.TCPMux.TLS.Clone()
	wrongHost.ServerName = "wrong.example.test"
	if err := handshakeWithServer(wrongHost, serverCertificate); err == nil {
		t.Fatal("wrong TLS hostname unexpectedly succeeded")
	}
	untrusted := endpoints.TCPMux.TLS.Clone()
	untrusted.RootCAs = x509.NewCertPool()
	if err := handshakeWithServer(untrusted, serverCertificate); err == nil {
		t.Fatal("untrusted TLS endpoint unexpectedly succeeded")
	}
	if len(key.Public()) != ed25519.PublicKeySize {
		t.Fatal("identity fixture did not create an Ed25519 key")
	}
}

func testEdgeServerCertificate(t *testing.T, now time.Time, identityValue connector.DataCarrierIdentity, edgeProcessEpoch string) (*x509.Certificate, tls.Certificate) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "preview-test-ca"},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(cryptorand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, serverPrivate, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "edge.example.test"},
		DNSNames: []string{"edge.example.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	serverDER, err := x509.CreateCertificate(cryptorand.Reader, serverTemplate, ca, serverPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_ = identityValue
	_ = edgeProcessEpoch
	return ca, tls.Certificate{Certificate: [][]byte{serverDER, caDER}, PrivateKey: serverPrivate}
}

func testEdgeServerTrust(t *testing.T, certificate tls.Certificate) (string, string) {
	t.Helper()
	if len(certificate.Certificate) == 0 {
		t.Fatal("edge certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	var chain bytes.Buffer
	for _, der := range certificate.Certificate {
		if err := pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			t.Fatal(err)
		}
	}
	return "sha256:" + hex.EncodeToString(digest[:]), chain.String()
}

func firstCertificateFromPEM(t *testing.T, chain string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(chain))
	if block == nil {
		t.Fatal("certificate PEM is empty")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func handshakeWithServer(clientConfig *tls.Config, serverCertificate tls.Certificate) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	serverErrors := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErrors <- acceptErr
			return
		}
		server := tls.Server(connection, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCertificate}, ClientAuth: tls.RequestClientCert})
		serverErrors <- server.Handshake()
		_ = server.Close()
	}()
	connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		return err
	}
	client := tls.Client(connection, clientConfig)
	clientErr := client.Handshake()
	_ = client.Close()
	serverErr := <-serverErrors
	if clientErr != nil {
		return clientErr
	}
	return serverErr
}

func newMachineAttachmentIdentity(t *testing.T) (string, *identity.Store) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "identity")
	store, err := identity.Open(identity.Config{StateRoot: root, Random: bytes.NewReader(bytes.Repeat([]byte{0x23}, ed25519.SeedSize))})
	if err != nil {
		t.Fatal(err)
	}
	key := store.Current()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	if err := store.SaveRegistration(identity.Registration{
		ServerURL: "https://api.example.test", MachineID: "host_01", EnvironmentID: "account_01",
		PublicKeyID: key.ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(key.Public()),
		InboxPath: filepath.Join(root, "inbox"), InstallationGeneration: 1, SetupMode: "host", SetupRoles: []string{"host"}, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	return root, store
}

func machineAttachmentAdmission(t *testing.T, store *identity.Store, now time.Time, identityValue connector.DataCarrierIdentity, endpoints []string) CarrierAdmission {
	t.Helper()
	_, attachment := providerTestLeaseAttachment(t, now, "preview_source", "operation_source_01", "route_source_01", identityValue, 1)
	key := store.Current()
	publicKey := base64.RawURLEncoding.EncodeToString(key.Public())
	attachment.EdgeEndpoints = append([]string(nil), endpoints...)
	attachment.Binding.MachineIdentityPublicKey = publicKey
	attachment.Binding.MachineIdentityThumbprint = machineIdentityThumbprint(publicKey)
	_, edgeCertificate := testEdgeServerCertificate(t, now, identityValue, attachment.Binding.EdgeProcessEpoch)
	attachment.Binding.EdgeCarrierServerSPKISHA256, attachment.Binding.EdgeCarrierServerCertificateChainPEM = testEdgeServerTrust(t, edgeCertificate)
	if err := attachment.Validate(now); err != nil {
		t.Fatal(err)
	}
	admission, err := attachment.Admission()
	if err != nil {
		t.Fatal(err)
	}
	return admission
}
