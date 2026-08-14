package peerendpoint

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/directpath"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/iceagent"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/nativepeer"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peersession"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/relaycarrier"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/relaynoise"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/signaling"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/udpsocket"
)

const (
	topologyControllingCredential = "controlling.payload.signature"
	topologyControlledCredential  = "controlled.payload.signature"
	topologyRequest               = "paperboat-direct-quic-request"
	topologyResponse              = "paperboat-direct-quic-response"
	topologyResponseAcknowledged  = "1"
)

func TestTopologyEndpointProcess(t *testing.T) {
	role := os.Getenv("PAPERBOAT_TOPOLOGY_ENDPOINT_ROLE")
	if role == "" {
		t.Skip("topology endpoint process mode is not configured")
	}
	if role == "auto-relay-initiator" || role == "auto-wss-initiator" {
		runTopologyAutoEndpoint(t, role)
		return
	}
	if role == "service-wss-initiator" {
		runTopologyHostServiceInitiator(t)
		return
	}
	if role == "relay-initiator" || role == "relay-responder" || role == "wss-initiator" || role == "wss-responder" || role == "health-relay-responder" || role == "health-wss-responder" {
		runTopologyRelayEndpoint(t, role)
		return
	}
	if role != "controlling" && role != "controlled" {
		t.Fatal("invalid topology endpoint role")
	}
	signalingURL := os.Getenv("PAPERBOAT_TOPOLOGY_SIGNALING_URL")
	stunURL := os.Getenv("PAPERBOAT_TOPOLOGY_STUN_URL")
	if signalingURL == "" || stunURL == "" {
		t.Fatal("topology service endpoints are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	credential := topologyControllingCredential
	localRole, remoteRole := signaling.RoleControlling, signaling.RoleControlled
	ufrag, password := "topologyA", "aaaaaaaaaaaaaaaaaaaaaa"
	if role == "controlled" {
		credential = topologyControlledCredential
		localRole, remoteRole = signaling.RoleControlled, signaling.RoleControlling
		ufrag, password = "topologyB", "bbbbbbbbbbbbbbbbbbbbbb"
	}
	transport, err := signaling.DialWebSocket(ctx, signaling.WebSocketConfig{URL: signalingURL, Credential: credential, TLS: topologySignalingTLS(t)})
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := directpath.Open(ctx, directpath.Config{
		ICE:     iceagent.Config{STUNURLs: []string{stunURL}, LocalUfrag: ufrag, LocalPwd: password},
		Sockets: udpsocket.DevelopmentConfig(true, false), PMTUKey: []byte("01234567890123456789012345678901"),
		MaximumPMTU: 1452, ApplicationQueue: 64, PMTUResponseLimit: time.Second,
		AttemptGeneration: 1, NetworkGeneration: 1,
	})
	if err != nil {
		_ = transport.Close()
		t.Fatal(err)
	}
	defer assembly.Close()
	localBinding := signaling.Binding{IntentID: "intent-topology", AttemptGeneration: 1, NetworkGeneration: 1, Role: localRole}
	remoteBinding := localBinding
	remoteBinding.Role = remoteRole
	if _, err := directpath.Negotiate(ctx, directpath.NegotiationConfig{
		Assembly: assembly, Transport: transport, LocalBinding: localBinding, RemoteBinding: remoteBinding,
		LocalUfrag: ufrag, LocalPassword: password,
	}); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("PAPERBOAT_TOPOLOGY_ICE_OK role=%s\n", role)
	waitTopologyQUICGate(t, ctx)
	clientTLS, serverTLS := topologyPeerTLS(t)
	recoveryGate := os.Getenv("PAPERBOAT_TOPOLOGY_QUIC_RECOVERY_GATE")
	if role == "controlled" {
		runTopologyQUICServer(t, ctx, assembly, serverTLS, recoveryGate != "")
		fmt.Println("PAPERBOAT_TOPOLOGY_CONTROLLED_QUIC_OK")
		return
	}
	runTopologyQUICClient(t, ctx, assembly, clientTLS, recoveryGate)
	fmt.Println("PAPERBOAT_TOPOLOGY_CONTROLLING_QUIC_OK")
}

type topologyRaceConnector struct {
	url      string
	wss      bool
	tls      *tls.Config
	lifetime context.Context
}

func (c topologyRaceConnector) Connect(ctx context.Context, attempt connectionmanager.Attempt) (connectionmanager.Connection, error) {
	switch attempt.Path {
	case connectionmanager.PathDirectQUIC:
		return nil, &connectionmanager.Failure{Class: connectionmanager.FailureReachability, Path: attempt.Path, Cause: errors.New("topology direct path deliberately unavailable")}
	case connectionmanager.PathRelayQUIC:
		if c.wss {
			return nil, &connectionmanager.Failure{Class: connectionmanager.FailureTransient, Path: attempt.Path, Cause: errors.New("topology relay UDP deliberately unavailable")}
		}
		connection, err := relaycarrier.DialQUIC(ctx, relaycarrier.QUICDialConfig{URL: c.url, Credential: "relay.payload.signature", EndpointID: "endpoint-cli", Role: "initiator", StreamHandle: topologyRelayHandle(), TLS: c.tls, Lifetime: c.lifetime, MaximumDeadline: 30 * time.Second, Carrier: relaycarrier.DevelopmentConfig()})
		if err != nil {
			return nil, &connectionmanager.Failure{Class: connectionmanager.FailureTransient, Path: attempt.Path, Cause: err}
		}
		return c.admitInitialHealth(ctx, connection, relaynoise.CarrierRelayQUIC, attempt.Path)
	case connectionmanager.PathWSS:
		connection, err := relaycarrier.DialWSS(ctx, relaycarrier.WSSDialConfig{URL: c.url, Credential: "relay.payload.signature", StreamHandle: topologyRelayHandle(), EndpointID: "endpoint-cli", Role: "initiator", RelayID: "relay-topology", TLS: c.tls, Lifetime: c.lifetime, MaximumDeadline: 30 * time.Second, Carrier: relaycarrier.DevelopmentConfig()})
		if err != nil {
			return nil, &connectionmanager.Failure{Class: connectionmanager.FailureTransient, Path: attempt.Path, Cause: err}
		}
		return c.admitInitialHealth(ctx, connection, relaynoise.CarrierWSS, attempt.Path)
	default:
		return nil, &connectionmanager.Failure{Class: connectionmanager.FailureInternal, Path: attempt.Path, Cause: errors.New("unexpected topology path")}
	}
}

func (c topologyRaceConnector) admitInitialHealth(ctx context.Context, connection *relaycarrier.Connection, carrier relaynoise.Carrier, path connectionmanager.Path) (connectionmanager.Connection, error) {
	initiatorKey, err := topologyRelayStaticKeyValue(11)
	if err != nil {
		return nil, &connectionmanager.Failure{Class: connectionmanager.FailureInternal, Path: path, Cause: err}
	}
	responderKey, err := topologyRelayStaticKeyValue(22)
	if err != nil {
		return nil, &connectionmanager.Failure{Class: connectionmanager.FailureInternal, Path: path, Cause: err}
	}
	source := relaycarrier.HealthConfigSourceFunc(func(_ context.Context, handle [16]byte) (relaycarrier.InitiatorConfig, error) {
		return relaycarrier.InitiatorConfig{LocalStatic: initiatorKey, ResponderPublic: topologyRelayPublic(responderKey), Prologue: topologyRelayHealthPrologue(carrier), Handle: handle}, nil
	})
	health, err := relaycarrier.NewHealthConnection(connection, source)
	if err != nil {
		return nil, &connectionmanager.Failure{Class: connectionmanager.FailureProtocol, Path: path, Cause: err}
	}
	nonce := [16]byte{}
	for index := range nonce {
		nonce[index] = 7
	}
	initial := relaycarrier.InitiatorConfig{LocalStatic: initiatorKey, ResponderPublic: topologyRelayPublic(responderKey), Prologue: topologyRelayInitialHealthPrologue(carrier), Handle: topologyRelayHealthHandle()}
	if err := health.AdmitInitialRelayHealth(ctx, initial, nonce); err != nil {
		return nil, &connectionmanager.Failure{Class: connectionmanager.FailureProtocol, Path: path, Cause: err}
	}
	return health, nil
}

func runTopologyAutoEndpoint(t *testing.T, role string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	wss := role == "auto-wss-initiator"
	url := os.Getenv("PAPERBOAT_TOPOLOGY_RELAY_URL")
	if url == "" {
		t.Fatal("topology relay URL is required")
	}
	racer, err := connectionmanager.NewRacer(connectionmanager.Config{RelayDelay: 25 * time.Millisecond, WSSDelay: 50 * time.Millisecond, ConnectTimeout: 10 * time.Second}, topologyRaceConnector{url: url, wss: wss, tls: topologyRelayTLS(t), lifetime: ctx})
	if err != nil {
		t.Fatal(err)
	}
	selection, err := racer.Connect(ctx, 1, connectionmanager.ModeAuto, connectionmanager.NetworkUnknown)
	if err != nil {
		t.Fatal(err)
	}
	wantPath := connectionmanager.PathRelayQUIC
	if wss {
		wantPath = connectionmanager.PathWSS
	}
	if selection.Path != wantPath {
		t.Fatalf("selected path=%d want=%d", selection.Path, wantPath)
	}
	selected, ok := selection.Connection.(*relaycarrier.HealthConnection)
	if !ok || selected.Connection == nil || selected.State() != connectionmanager.StateTrusted {
		t.Fatal("selected connection lost real relay carrier")
	}
	defer selected.Close()
	initiatorKey := topologyRelayStaticKey(t, 11)
	responderKey := topologyRelayStaticKey(t, 22)
	carrier := relaynoise.CarrierRelayQUIC
	if wss {
		carrier = relaynoise.CarrierWSS
	}
	stream, response, err := selected.Connection.Initiate(ctx, relaycarrier.InitiatorConfig{LocalStatic: initiatorKey, ResponderPublic: topologyRelayPublic(responderKey), Prologue: topologyRelayPrologue(carrier), Handle: topologyRelayHandle(), InitialPayload: []byte("paperboat-relay-open")})
	if err != nil || string(response) != "paperboat-relay-accepted" {
		t.Fatalf("selected path Noise response=%q error=%v", response, err)
	}
	defer stream.Close()
	if err := stream.Send(ctx, []byte("paperboat-relay-request"), false); err != nil {
		t.Fatal(err)
	}
	response, closed, err := stream.Receive(ctx)
	if err != nil || closed || string(response) != "paperboat-relay-response" {
		t.Fatalf("selected path response=%q closed=%t error=%v", response, closed, err)
	}
	if err := stream.Send(ctx, []byte("paperboat-relay-ack"), true); err != nil {
		t.Fatal(err)
	}
	if wss {
		fmt.Println("PAPERBOAT_TOPOLOGY_AUTO_WSS_OK")
	} else {
		fmt.Println("PAPERBOAT_TOPOLOGY_AUTO_RELAY_OK")
	}
	waitTopologyRelayExitGate(t, ctx)
}

func runTopologyHostServiceInitiator(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var descriptor api.PeerAttemptDescriptor
	for {
		encoded, err := os.ReadFile(topologyAuthorityPath())
		if err == nil {
			if err := json.Unmarshal(encoded, &descriptor); err != nil {
				t.Fatal(err)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		select {
		case <-time.After(25 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	descriptor.Role = "controlling"
	rootPublic := topologyHostRootPrivate().Public().(ed25519.PublicKey)
	initiatorCertificate := topologyDescriptorCertificate(t, descriptor, descriptor.InitiatorEndpointID, rootPublic, endpointidentity.RoleCLI)
	responderCertificate := topologyDescriptorCertificate(t, descriptor, descriptor.ResponderEndpointID, rootPublic, endpointidentity.RoleMachine)
	initiatorPrivate := topologyHostInitiatorNoisePrivate(t)
	authority, err := peersession.New(peersession.Config{Descriptor: descriptor, LocalCertificate: initiatorCertificate, PeerCertificate: responderCertificate, LocalNoisePrivate: initiatorPrivate, Consumer: "terminal"})
	if err != nil {
		t.Fatal(err)
	}
	relay := descriptor.Relays[0]
	connection, err := relaycarrier.DialWSS(ctx, relaycarrier.WSSDialConfig{URL: relay.WSSURL, Credential: relay.RouteToken, StreamHandle: authority.RouteHandle, EndpointID: authority.LocalEndpointID(), Role: "initiator", RelayID: relay.Region, TLS: topologyRelayTLS(t), Lifetime: ctx, MaximumDeadline: 30 * time.Second, Carrier: relaycarrier.DevelopmentConfig()})
	if err != nil {
		t.Fatal(err)
	}
	healthAuthority, err := authority.Initiator("native-health")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := relaycarrier.PeerInitiatorConfig(healthAuthority, connection.Carrier(), "native-health", nil)
	if err != nil {
		t.Fatal(err)
	}
	health, err := relaycarrier.NewHealthConnection(connection, relaycarrier.HealthConfigSourceFunc(func(_ context.Context, handle [16]byte) (relaycarrier.InitiatorConfig, error) {
		periodic := healthAuthority
		periodic.Handle = handle
		return relaycarrier.PeerInitiatorConfig(periodic, connection.Carrier(), "native-health", nil)
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer health.Close()
	var nonce [16]byte
	for index := range nonce {
		nonce[index] = 9
	}
	if err := health.AdmitInitialRelayHealth(ctx, initial, nonce); err != nil {
		t.Fatal(err)
	}
	initiator := nativepeer.Initiator{Connection: connection, Authority: authority}
	for index, streamID := range []string{"native-control", "native-input", "native-output"} {
		stream, err := initiator.Open(ctx, streamID)
		if err != nil {
			t.Fatal(err)
		}
		payload := []byte{byte(index + 1)}
		if _, err := stream.Write(payload); err != nil {
			_ = stream.Close()
			t.Fatal(err)
		}
		response := make([]byte, 1)
		if _, err := io.ReadFull(stream, response); err != nil || !bytes.Equal(response, payload) {
			_ = stream.Close()
			t.Fatalf("stream %s response=%x error=%v", streamID, response, err)
		}
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Println("PAPERBOAT_TOPOLOGY_HOST_SERVICE_CLIENT_OK")
	waitTopologyRelayExitGate(t, ctx)
}

func topologyHostRootPrivate() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, ed25519.SeedSize))
}

func topologyHostInitiatorNoisePrivate(t *testing.T) [32]byte {
	t.Helper()
	private, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{17}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var result [32]byte
	copy(result[:], private.Bytes())
	return result
}

func topologyDescriptorCertificate(t *testing.T, descriptor api.PeerAttemptDescriptor, endpointID string, root ed25519.PublicKey, role endpointidentity.Role) endpointidentity.Certificate {
	t.Helper()
	for _, document := range descriptor.EndpointCertificates {
		if document.EndpointID != endpointID {
			continue
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(document.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := endpointidentity.Verify(raw, root, endpointidentity.Expected{AccountID: descriptor.AccountID, Role: role, EndpointID: endpointID}, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		return certificate
	}
	t.Fatal("topology endpoint certificate missing")
	return endpointidentity.Certificate{}
}

func topologyAuthorityPath() string { return "/authority/descriptor.json" }

func runTopologyRelayEndpoint(t *testing.T, role string) {
	relayURL := os.Getenv("PAPERBOAT_TOPOLOGY_RELAY_URL")
	if relayURL == "" {
		t.Fatal("topology relay URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	initiatorKey := topologyRelayStaticKey(t, 11)
	responderKey := topologyRelayStaticKey(t, 22)
	handle := [16]byte{}
	for index := range handle {
		handle[index] = 3
	}
	wss := role == "wss-initiator" || role == "wss-responder" || role == "health-wss-responder"
	carrier := relaynoise.CarrierRelayQUIC
	if wss {
		carrier = relaynoise.CarrierWSS
	}
	prologue := topologyRelayPrologue(carrier)
	endpointID, relayRole := "endpoint-cli", "initiator"
	responder := role == "relay-responder" || role == "wss-responder" || role == "health-relay-responder" || role == "health-wss-responder"
	initialHealth := role == "health-relay-responder" || role == "health-wss-responder"
	if responder {
		endpointID, relayRole = "endpoint-host", "responder"
	}
	var connection *relaycarrier.Connection
	var err error
	if wss {
		connection, err = relaycarrier.DialWSS(ctx, relaycarrier.WSSDialConfig{
			URL: relayURL, Credential: "relay.payload.signature", StreamHandle: handle, EndpointID: endpointID, Role: relayRole,
			RelayID: "relay-topology", TLS: topologyRelayTLS(t), Lifetime: ctx, MaximumDeadline: 30 * time.Second, Carrier: relaycarrier.DevelopmentConfig(),
		})
	} else {
		connection, err = relaycarrier.DialQUIC(ctx, relaycarrier.QUICDialConfig{
			URL: relayURL, Credential: "relay.payload.signature", EndpointID: endpointID, Role: relayRole, StreamHandle: handle,
			TLS: topologyRelayTLS(t), Lifetime: ctx, MaximumDeadline: 30 * time.Second, Carrier: relaycarrier.DevelopmentConfig(),
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if responder {
		if initialHealth {
			prefix, err := connection.AcceptInitialHealth(ctx, relaycarrier.ResponderConfig{LocalStatic: responderKey, InitiatorPublic: topologyRelayPublic(initiatorKey), Prologue: topologyRelayInitialHealthPrologue(carrier), Handle: topologyRelayHealthHandle()})
			if err != nil || prefix.Prefix == [8]byte{} {
				t.Fatalf("accept initial relay health prefix=%x error=%v", prefix, err)
			}
			fmt.Println("PAPERBOAT_TOPOLOGY_INITIAL_HEALTH_OK")
		}
		stream, initial, err := connection.Accept(ctx, relaycarrier.ResponderConfig{
			LocalStatic: responderKey, InitiatorPublic: topologyRelayPublic(initiatorKey), Prologue: prologue, Handle: handle,
			Authorize: func(_ context.Context, request []byte) ([]byte, error) {
				if string(request) != "paperboat-relay-open" {
					return nil, relaycarrier.ErrInvalid
				}
				return []byte("paperboat-relay-accepted"), nil
			},
		})
		if err != nil || string(initial) != "paperboat-relay-open" {
			t.Fatalf("accept initial=%q error=%v", initial, err)
		}
		defer stream.Close()
		request, closed, err := stream.Receive(ctx)
		if err != nil || closed || string(request) != "paperboat-relay-request" {
			t.Fatalf("relay request=%q closed=%t error=%v", request, closed, err)
		}
		if err := stream.Send(ctx, []byte("paperboat-relay-response"), false); err != nil {
			t.Fatal(err)
		}
		acknowledgment, closed, err := stream.Receive(ctx)
		if err != nil || !closed || string(acknowledgment) != "paperboat-relay-ack" {
			t.Fatalf("relay acknowledgment=%q closed=%t error=%v", acknowledgment, closed, err)
		}
		if wss {
			fmt.Println("PAPERBOAT_TOPOLOGY_WSS_RESPONDER_OK")
		} else {
			fmt.Println("PAPERBOAT_TOPOLOGY_RELAY_RESPONDER_OK")
		}
		waitTopologyRelayExitGate(t, ctx)
		return
	}
	stream, response, err := connection.Initiate(ctx, relaycarrier.InitiatorConfig{
		LocalStatic: initiatorKey, ResponderPublic: topologyRelayPublic(responderKey), Prologue: prologue, Handle: handle,
		InitialPayload: []byte("paperboat-relay-open"),
	})
	if err != nil || string(response) != "paperboat-relay-accepted" {
		t.Fatalf("initiate response=%q error=%v", response, err)
	}
	defer stream.Close()
	if err := stream.Send(ctx, []byte("paperboat-relay-request"), false); err != nil {
		t.Fatal(err)
	}
	response, closed, err := stream.Receive(ctx)
	if err != nil || closed || string(response) != "paperboat-relay-response" {
		t.Fatalf("relay response=%q closed=%t error=%v", response, closed, err)
	}
	if err := stream.Send(ctx, []byte("paperboat-relay-ack"), true); err != nil {
		t.Fatal(err)
	}
	if wss {
		fmt.Println("PAPERBOAT_TOPOLOGY_WSS_INITIATOR_OK")
	} else {
		fmt.Println("PAPERBOAT_TOPOLOGY_RELAY_INITIATOR_OK")
	}
	waitTopologyRelayExitGate(t, ctx)
}

func waitTopologyRelayExitGate(t *testing.T, ctx context.Context) {
	t.Helper()
	if gate := os.Getenv("PAPERBOAT_TOPOLOGY_RELAY_EXIT_GATE"); gate != "" {
		waitTopologyGate(t, ctx, gate)
	}
}

func topologyRelayStaticKey(t *testing.T, value byte) noise.DHKey {
	t.Helper()
	key, err := topologyRelayStaticKeyValue(value)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func topologyRelayStaticKeyValue(value byte) (noise.DHKey, error) {
	return noise.DH25519.GenerateKeypair(bytes.NewReader(bytes.Repeat([]byte{value}, 32)))
}

func topologyRelayHandle() [16]byte {
	var handle [16]byte
	for index := range handle {
		handle[index] = 3
	}
	return handle
}

func topologyRelayHealthHandle() [16]byte {
	var handle [16]byte
	for index := range handle {
		handle[index] = 5
	}
	return handle
}

func topologyRelayInitialHealthPrologue(carrier relaynoise.Carrier) relaynoise.Prologue {
	prologue := topologyRelayPrologue(carrier)
	prologue.StreamID = "initial-health"
	return prologue
}

func topologyRelayHealthPrologue(carrier relaynoise.Carrier) relaynoise.Prologue {
	prologue := topologyRelayPrologue(carrier)
	prologue.StreamID = "active-health"
	return prologue
}

func topologyRelayPublic(key noise.DHKey) [32]byte {
	var public [32]byte
	copy(public[:], key.Public)
	return public
}

func topologyRelayPrologue(carrier relaynoise.Carrier) relaynoise.Prologue {
	value := peercontext.Context{
		AccountID: "account-topology", UserID: "user-topology", DeviceID: "device-topology", MachineID: "machine-topology",
		HostGeneration: 1, AuthorizationGeneration: 1, IntentID: "intent-topology", OperationID: "operation-topology",
		Consumer: "terminal", InitiatorRole: "cli", ResponderRole: "machine", AttemptGeneration: 1,
	}
	for index := range value.InitiatorCertificateHash {
		value.InitiatorCertificateHash[index] = 1
		value.ResponderCertificateHash[index] = 2
	}
	return relaynoise.Prologue{Context: value, Carrier: carrier, StreamID: "stream-topology"}
}

func topologyRelayTLS(t *testing.T) *tls.Config {
	t.Helper()
	seed := bytes.Repeat([]byte{31}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "relay.paperboat.test"},
		NotBefore: time.Unix(1_577_836_800, 0), NotAfter: time.Unix(4_102_444_800, 0),
		DNSNames: []string{"relay.paperboat.test"}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, private.Public(), private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "relay.paperboat.test"}
}

func waitTopologyQUICGate(t *testing.T, ctx context.Context) {
	t.Helper()
	gate := os.Getenv("PAPERBOAT_TOPOLOGY_QUIC_GATE")
	if gate == "" {
		return
	}
	waitTopologyGate(t, ctx, gate)
}

func runTopologyQUICServer(t *testing.T, ctx context.Context, assembly *directpath.Assembly, config *tls.Config, verifyRecovery bool) {
	t.Helper()
	listener, err := assembly.ListenProbeQUIC(ctx, config, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	session, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	stream, err := session.Connection.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	rounds := 1
	if verifyRecovery {
		rounds = 2
	}
	for round := 0; round < rounds; round++ {
		request := make([]byte, len(topologyRequest))
		if _, err := io.ReadFull(stream, request); err != nil || string(request) != topologyRequest {
			t.Fatalf("QUIC request=%q error=%v", request, err)
		}
		if err := writeTopologyPayload(stream, topologyResponse); err != nil {
			t.Fatal(err)
		}
		if round == 0 && verifyRecovery {
			fmt.Println("PAPERBOAT_TOPOLOGY_CONTROLLED_BASELINE_OK")
		}
	}
	acknowledgment := make([]byte, len(topologyResponseAcknowledged))
	if _, err := io.ReadFull(stream, acknowledgment); err != nil || string(acknowledgment) != topologyResponseAcknowledged {
		t.Fatalf("QUIC acknowledgment=%q error=%v", acknowledgment, err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
}

func runTopologyQUICClient(t *testing.T, ctx context.Context, assembly *directpath.Assembly, config *tls.Config, recoveryGate string) {
	t.Helper()
	session, err := assembly.DialProbeQUIC(ctx, config, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	stream, err := session.Connection.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	rounds := 1
	if recoveryGate != "" {
		rounds = 2
	}
	for round := 0; round < rounds; round++ {
		if round == 1 {
			waitTopologyGate(t, ctx, recoveryGate)
			fmt.Println("PAPERBOAT_TOPOLOGY_RECOVERY_SEND_STARTED")
		}
		if err := writeTopologyPayload(stream, topologyRequest); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, len(topologyResponse))
		if _, err := io.ReadFull(stream, response); err != nil || string(response) != topologyResponse {
			t.Fatalf("QUIC response=%q error=%v", response, err)
		}
		if round == 0 && recoveryGate != "" {
			fmt.Println("PAPERBOAT_TOPOLOGY_CONTROLLING_BASELINE_OK")
		}
	}
	if err := writeTopologyPayload(stream, topologyResponseAcknowledged); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	var remoteClose [1]byte
	if count, err := stream.Read(remoteClose[:]); count != 0 || err == nil {
		t.Fatalf("QUIC remote close count=%d error=%v", count, err)
	}
}

func waitTopologyGate(t *testing.T, ctx context.Context, gate string) {
	t.Helper()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(gate); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
}

func writeTopologyPayload(writer io.Writer, payload string) error {
	for remaining := []byte(payload); len(remaining) > 0; {
		written, err := writer.Write(remaining)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		remaining = remaining[written:]
	}
	return nil
}

func topologySignalingTLS(t *testing.T) *tls.Config {
	t.Helper()
	seed := [ed25519.SeedSize]byte{1, 9, 8, 4, 2, 7, 6, 5, 3, 8, 1, 4, 9, 2, 6, 7, 5, 3, 8, 1, 4, 9, 2, 6, 7, 5, 3, 8, 1, 4, 9, 2}
	private := ed25519.NewKeyFromSeed(seed[:])
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "signaling.paperboat.test"},
		NotBefore: time.Unix(1_577_836_800, 0), NotAfter: time.Unix(4_102_444_800, 0),
		DNSNames: []string{"signaling.paperboat.test"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, private.Public(), private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "signaling.paperboat.test"}
}

func topologyPeerTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	rootSeed := [ed25519.SeedSize]byte{7, 1, 3, 9, 2, 8, 4, 6, 5, 7, 1, 3, 9, 2, 8, 4, 6, 5, 7, 1, 3, 9, 2, 8, 4, 6, 5, 7, 1, 3, 9, 2}
	rootPrivate := ed25519.NewKeyFromSeed(rootSeed[:])
	rootPublic := rootPrivate.Public().(ed25519.PublicKey)
	issuedAt, expiresAt := time.Unix(1_577_836_800, 0), time.Unix(4_102_444_800, 0)
	issue := func(seedByte byte, serial uint64, role endpointidentity.Role, endpointID string) (endpointidentity.Certificate, tls.Certificate) {
		seed := [ed25519.SeedSize]byte{}
		for index := range seed {
			seed[index] = seedByte + byte(index%7)
		}
		private := ed25519.NewKeyFromSeed(seed[:])
		var noise [32]byte
		for index := range noise {
			noise[index] = seedByte ^ byte(index)
		}
		certificate, err := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{
			AccountID: "account-topology", Role: role, EndpointID: endpointID, NoisePublicKey: noise,
			QUICPublicKey: private.Public().(ed25519.PublicKey), Generation: 1, Serial: serial,
			IssuedAt: issuedAt, ExpiresAt: expiresAt,
		})
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := endpointidentity.NewTLSCertificate(certificate, rootPublic, private, time.Now().UTC(), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return certificate, leaf
	}
	clientCertificate, clientLeaf := issue(10, 1, endpointidentity.RoleCLI, "cli-topology")
	serverCertificate, serverLeaf := issue(20, 2, endpointidentity.RoleMachine, "machine-topology")
	clientRaw, err := clientCertificate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	serverRaw, err := serverCertificate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now
	client, err := endpointidentity.ClientTLS(clientLeaf, endpointidentity.PeerExpectation{
		RootPublic: rootPublic, Certificate: serverRaw,
		Expected: endpointidentity.Expected{AccountID: "account-topology", Role: endpointidentity.RoleMachine, EndpointID: "machine-topology", Generation: 1},
	}, peerquic.ALPN, clock)
	if err != nil {
		t.Fatal(err)
	}
	server, err := endpointidentity.ServerTLS(serverLeaf, endpointidentity.PeerExpectation{
		RootPublic: rootPublic, Certificate: clientRaw,
		Expected: endpointidentity.Expected{AccountID: "account-topology", Role: endpointidentity.RoleCLI, EndpointID: "cli-topology", Generation: 1},
	}, peerquic.ALPN, clock)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}
