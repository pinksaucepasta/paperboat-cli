package directpath

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/iceagent"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkadaptation"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkcheck"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/udpsocket"
)

type assemblySTUNObserver struct {
	called bool
	port   int
	urls   []string
	result networkcheck.STUNObservation
}

func (o *assemblySTUNObserver) Observe(_ context.Context, ipv4, ipv6 net.PacketConn, urls []string) networkcheck.STUNObservation {
	o.called = true
	if ipv4 != nil {
		o.port = ipv4.LocalAddr().(*net.UDPAddr).Port
	} else if ipv6 != nil {
		o.port = ipv6.LocalAddr().(*net.UDPAddr).Port
	}
	o.urls = append([]string(nil), urls...)
	return o.result
}

func TestAssemblyObservesSTUNOnOwnedSocketBeforeICE(t *testing.T) {
	observer := &assemblySTUNObserver{result: networkcheck.STUNObservation{IPv4: "destination_dependent", IPv6: "unknown", CaptivePortal: "clear", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}}
	config := assemblyConfig("stun-observer", "password-123456789012345678901234", bytes.Repeat([]byte{8}, 32))
	config.ICE.STUNURLs = []string{"stun:a.example.test:3478", "stun:b.example.test:3478"}
	config.STUNObserver, config.STUNProbeTimeout = observer, time.Second
	assembly, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer assembly.Close()
	if !observer.called || observer.port == 0 || observer.port != int(assembly.Port()) || len(observer.urls) != 2 || assembly.STUNObservation() != observer.result {
		t.Fatalf("observer=%#v assembly=%#v", observer, assembly.STUNObservation())
	}
}

func TestAssembliesStartQUICAtSafePMTUWithoutBlockingProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key := bytes.Repeat([]byte{31}, 32)
	leftConfig := assemblyConfig("left-direct-path", "left-password-123456789012345678901234", key)
	rightConfig := assemblyConfig("right-direct-path", "right-password-12345678901234567890123", key)
	left, err := Open(ctx, leftConfig)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Open(ctx, rightConfig)
	if err != nil {
		_ = left.Close()
		t.Fatal(err)
	}
	defer right.Close()
	defer left.Close()
	if left.Port() == 0 || right.Port() == 0 {
		t.Fatal("owned socket port not published")
	}
	if _, err := left.SelectedPMTUExchanger(); err == nil {
		t.Fatal("PMTU exchanger available before ICE nomination")
	}
	leftCandidates := gather(t, ctx, left)
	rightCandidates := gather(t, ctx, right)
	for _, candidate := range leftCandidates {
		if err := right.AddRemoteCandidate(candidate); err != nil {
			t.Fatal(err)
		}
	}
	for _, candidate := range rightCandidates {
		if err := left.AddRemoteCandidate(candidate); err != nil {
			t.Fatal(err)
		}
	}

	var wait sync.WaitGroup
	wait.Add(1)
	var rightConn net.Conn
	var rightErr error
	go func() {
		defer wait.Done()
		rightConn, rightErr = right.Connect(ctx, iceagent.RoleControlled, leftConfig.ICE.LocalUfrag, leftConfig.ICE.LocalPwd)
	}()
	leftConn, err := left.Connect(ctx, iceagent.RoleControlling, rightConfig.ICE.LocalUfrag, rightConfig.ICE.LocalPwd)
	if err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	if rightErr != nil {
		t.Fatal(rightErr)
	}
	defer rightConn.Close()
	defer leftConn.Close()

	clientTLS, serverTLS := directPathTLS(t)
	policy := networkadaptation.DevelopmentPMTUPolicy()
	leftCache, _ := networkadaptation.NewPMTUCache(policy)
	rightCache, _ := networkadaptation.NewPMTUCache(policy)
	leftKey := directPMTUKey(t, 1)
	rightKey := directPMTUKey(t, 2)
	base := peerquic.DevelopmentSessionConfig(peerquic.ClassInteractive)
	listener, err := right.ListenQUIC(ctx, serverTLS, base, PMTUConfig{Policy: policy, Cache: rightCache, Key: rightKey})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *peerquic.Session, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		session, acceptErr := listener.Accept(ctx)
		if acceptErr != nil {
			acceptErrors <- acceptErr
			return
		}
		accepted <- session
	}()
	client, err := left.DialQUIC(ctx, clientTLS, base, PMTUConfig{Policy: policy, Cache: leftCache, Key: leftKey})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := NewHealthConnection(left, client)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	var server *peerquic.Session
	select {
	case server = <-accepted:
	case err := <-acceptErrors:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	serverConnection, err := NewHealthConnection(right, server)
	if err != nil {
		t.Fatal(err)
	}
	defer serverConnection.Close()
	router, err := peerquic.NewStreamRouter(server, peerquic.DevelopmentStreamRouterConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	servedHealth := make(chan error, 1)
	go func() { servedHealth <- serverConnection.AdmitInitialHealthResponse(ctx, router) }()
	var healthNonce [16]byte
	copy(healthNonce[:], "initial-direct-ok")
	if err := connection.AdmitInitialHealth(ctx, healthNonce); err != nil {
		t.Fatal(err)
	}
	if err := <-servedHealth; err != nil {
		t.Fatal(err)
	}
	if serverConnection.State() != connectionmanager.StateTrusted {
		t.Fatalf("responder state=%d", serverConnection.State())
	}
	transport, err := connectionmanager.ConnectionHealthTransport(connectionmanager.Selection{Generation: 1, Path: connectionmanager.PathDirectQUIC, Connection: connection})
	if err != nil || transport != connection {
		t.Fatalf("direct health transport=%T error=%v", transport, err)
	}
	if _, err := connectionmanager.ConnectionHealthTransport(connectionmanager.Selection{Generation: 1, Path: connectionmanager.PathRelayQUIC, Connection: connection}); err == nil {
		t.Fatal("accepted direct health capability as relay QUIC")
	}
	for name, item := range map[string]struct {
		cache *networkadaptation.PMTUCache
		key   networkadaptation.PMTUKey
	}{"left": {leftCache, leftKey}, "right": {rightCache, rightKey}} {
		observation, ok := item.cache.Lookup(item.key, time.Now().UTC())
		if ok {
			t.Fatalf("%s unexpected synchronous PMTU observation=%+v", name, observation)
		}
	}
	stream, err := client.Connection.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("configured-direct-native-quic")
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	serverStream, err := router.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(serverStream, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("payload=%q", received)
	}
	response := make([]byte, 256<<10)
	for index := range response {
		response[index] = byte(index*131 + 17)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := serverStream.Write(response)
		writeDone <- errors.Join(writeErr, serverStream.Close())
	}()
	receivedResponse, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(receivedResponse, response) {
		t.Fatalf("response length=%d want=%d", len(receivedResponse), len(response))
	}

	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if left.Port() != 0 {
		t.Fatal("owned port remained published after close")
	}
	if _, err := left.SelectedPMTUExchanger(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed PMTU exchanger error=%v", err)
	}
	if connection.State() != connectionmanager.StateFailed {
		t.Fatal("direct connection remained trusted after assembly closure")
	}
}

func TestDirectHealthFailureTypesOnlyExplicitResponseTimeout(t *testing.T) {
	typed := directHealthFailure(peerquic.ErrLifetimeProbeUnreachable)
	var failure *connectionmanager.Failure
	if !errors.As(typed, &failure) || failure.Class != connectionmanager.FailureTimeout || failure.Path != connectionmanager.PathDirectQUIC || !failure.AllowsFallback() {
		t.Fatalf("typed failure=%v", typed)
	}
	protocol := errors.New("invalid health response")
	if got := directHealthFailure(protocol); got != protocol {
		t.Fatalf("protocol failure changed to %v", got)
	}
	if directHealthFailure(nil) != nil {
		t.Fatal("nil failure changed")
	}
}

func directPMTUKey(t *testing.T, marker byte) networkadaptation.PMTUKey {
	t.Helper()
	fingerprint, err := networkadaptation.DeriveFingerprint(bytes.Repeat([]byte{marker}, 32), networkadaptation.NetworkObservation{
		Interfaces:       []networkadaptation.Interface{{Name: "loopback", Kind: networkadaptation.InterfacePhysical, Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}},
		DefaultInterface: "loopback", NetworkIdentity: "direct-path-test", IPv4: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return networkadaptation.PMTUKey{Fingerprint: fingerprint, PathID: "direct-loopback", NetworkGeneration: 1}
}

func directPathTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	issue := func(serial uint64, role endpointidentity.Role, endpointID string) (endpointidentity.Certificate, tls.Certificate) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		var noise [32]byte
		if _, err := rand.Read(noise[:]); err != nil {
			t.Fatal(err)
		}
		certificate, err := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{
			AccountID: "account_01", Role: role, EndpointID: endpointID, NoisePublicKey: noise,
			QUICPublicKey: public, Generation: 1, Serial: serial, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := endpointidentity.NewTLSCertificate(certificate, rootPublic, private, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return certificate, leaf
	}
	clientCertificate, clientLeaf := issue(2, endpointidentity.RoleCLI, "cli_01")
	serverCertificate, serverLeaf := issue(3, endpointidentity.RoleMachine, "machine_01")
	clientRaw, _ := clientCertificate.MarshalBinary()
	serverRaw, _ := serverCertificate.MarshalBinary()
	clock := func() time.Time { return now }
	client, err := endpointidentity.ClientTLS(clientLeaf, endpointidentity.PeerExpectation{
		RootPublic: rootPublic, Certificate: serverRaw,
		Expected: endpointidentity.Expected{AccountID: "account_01", Role: endpointidentity.RoleMachine, EndpointID: "machine_01", Generation: 1},
	}, peerquic.ALPN, clock)
	if err != nil {
		t.Fatal(err)
	}
	server, err := endpointidentity.ServerTLS(serverLeaf, endpointidentity.PeerExpectation{
		RootPublic: rootPublic, Certificate: clientRaw,
		Expected: endpointidentity.Expected{AccountID: "account_01", Role: endpointidentity.RoleCLI, EndpointID: "cli_01", Generation: 1},
	}, peerquic.ALPN, clock)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestOpenRejectsMissingGenerations(t *testing.T) {
	config := assemblyConfig("invalid", "invalid-password-123456789012345678901", bytes.Repeat([]byte{32}, 32))
	config.NetworkGeneration = 0
	if assembly, err := Open(context.Background(), config); err == nil || assembly != nil {
		if assembly != nil {
			_ = assembly.Close()
		}
		t.Fatalf("assembly=%v err=%v", assembly, err)
	}
}

func assemblyConfig(ufrag, password string, key []byte) Config {
	return Config{
		ICE:     iceagent.Config{LocalUfrag: ufrag, LocalPwd: password},
		Sockets: udpsocket.DevelopmentConfig(true, false), PMTUKey: key,
		MaximumPMTU: 1452, ApplicationQueue: 64, PMTUResponseLimit: time.Second,
		AttemptGeneration: 1, NetworkGeneration: 1,
	}
}

func gather(t *testing.T, ctx context.Context, assembly *Assembly) []string {
	t.Helper()
	var candidates []string
	if err := assembly.Gather(ctx, func(candidate string) error {
		candidates = append(candidates, candidate)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(candidates) == 0 {
		t.Fatal("no candidates gathered")
	}
	return candidates
}
