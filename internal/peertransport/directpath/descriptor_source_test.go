package directpath

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

type peerAttemptClientFunc func(context.Context, api.PeerAttemptInput) (api.PeerAttemptDescriptor, error)

func (f peerAttemptClientFunc) CreatePeerAttempt(ctx context.Context, input api.PeerAttemptInput) (api.PeerAttemptDescriptor, error) {
	return f(ctx, input)
}

func TestAPIDescriptorSourceValidatesAndMapsDirectAuthority(t *testing.T) {
	now := time.Unix(2000, 0).UTC()
	document := peerAttemptDocument(t, now)
	controllingFingerprint, controlledFingerprint := documentFingerprints(t, document)
	var acquired AttemptDescriptor
	source, err := NewAPIDescriptorSource(APIDescriptorSourceConfig{Client: peerAttemptClientFunc(func(_ context.Context, input api.PeerAttemptInput) (api.PeerAttemptDescriptor, error) {
		if input.AttemptGeneration != 2 || input.NetworkGeneration != 4 || input.OperationID != "peer-operation-2-4" || input.RelayLatency == nil || input.RelayLatency.Generation != 7 {
			t.Fatalf("input=%+v", input)
		}
		return document, nil
	}), EnvironmentID: "env_1", Purpose: "interactive", Consumer: "terminal", AccountID: "account_1", RootPublicKey: testDescriptorRoot().Public().(ed25519.PublicKey), ControllingEndpointID: document.InitiatorEndpointID, ControlledEndpointID: document.ResponderEndpointID, ControllingCertificateFingerprint: controllingFingerprint, ControlledCertificateFingerprint: controlledFingerprint, RelayLatency: func() *api.RelayLatencyVector {
		return &api.RelayLatencyVector{Generation: 7, ObservedAt: now, Samples: []api.RelayLatencySample{{Region: "fsn1", RTTMS: 20}}}
	}, OperationID: func(generation Generation) string {
		return "peer-operation-" + string(rune('0'+generation.Attempt)) + "-" + string(rune('0'+generation.Network))
	}, OnAcquire: func(value AttemptDescriptor) { acquired = value }})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := source.Acquire(context.Background(), Generation{Attempt: 2, Network: 4})
	if err != nil || descriptor.Document.OperationID != document.OperationID || descriptor.Document.HostGeneration != document.HostGeneration || descriptor.Document.AuthorizationGeneration != document.AuthorizationGeneration || descriptor.IntentID != document.IntentID || descriptor.SignalingURL != document.Signaling.URL || descriptor.RelayQUICURL != document.Relays[0].QUICURL || descriptor.RelayWSSURL != document.Relays[0].WSSURL || descriptor.RelayCredential != document.Relays[0].RouteToken || descriptor.RouteGeneration != 1 || descriptor.LocalUfrag != document.Direct.ICEUfrag || len(descriptor.STUNURLs) != 1 {
		t.Fatalf("descriptor=%+v err=%v", descriptor, err)
	}
	if acquired.IntentID != descriptor.IntentID || acquired.AttemptGeneration != descriptor.AttemptGeneration {
		t.Fatalf("acquisition callback=%+v descriptor=%+v", acquired, descriptor)
	}
}

func TestAPIDescriptorSourceRejectsAuthoritySubstitutionAndClassifiesFallback(t *testing.T) {
	now := time.Unix(2000, 0).UTC()
	for name, mutate := range map[string]func(*api.PeerAttemptDescriptor){
		"missing relay": func(value *api.PeerAttemptDescriptor) { value.Relays = nil },
		"QUIC substitution": func(value *api.PeerAttemptDescriptor) {
			value.Relays[0].QUICURL = "http://signal.example.test/v1/peer-relay"
		},
		"changed role": func(value *api.PeerAttemptDescriptor) { value.Role = "controlled" },
		"certificate swap": func(value *api.PeerAttemptDescriptor) {
			value.EndpointCertificates[0].EndpointID = value.ResponderEndpointID
		},
	} {
		t.Run(name, func(t *testing.T) {
			document := peerAttemptDocument(t, now)
			mutate(&document)
			source := descriptorSourceForTest(t, func(context.Context, api.PeerAttemptInput) (api.PeerAttemptDescriptor, error) { return document, nil })
			if _, err := source.Acquire(context.Background(), Generation{Attempt: 2, Network: 4}); !errors.Is(err, ErrDescriptorInvalid) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	source := descriptorSourceForTest(t, func(context.Context, api.PeerAttemptInput) (api.PeerAttemptDescriptor, error) {
		return api.PeerAttemptDescriptor{}, &api.APIError{Status: 503, Code: "route_unavailable"}
	})
	if _, err := source.Acquire(context.Background(), Generation{Attempt: 2, Network: 4}); !errors.Is(err, ErrDescriptorUnavailable) {
		t.Fatalf("fallback error=%v", err)
	}
}

func TestAPIDescriptorSourceBindsDirectProbePurposeAndPolicy(t *testing.T) {
	now := time.Unix(2000, 0).UTC()
	document := peerAttemptDocument(t, now)
	document.Purpose = "direct_probe"
	document.Consumer = "terminal"
	document.Policy.AllowedPaths = []string{"direct_quic"}
	controllingFingerprint, controlledFingerprint := documentFingerprints(t, document)
	source, err := NewAPIDescriptorSource(APIDescriptorSourceConfig{Client: peerAttemptClientFunc(func(_ context.Context, input api.PeerAttemptInput) (api.PeerAttemptDescriptor, error) {
		if input.Purpose != "direct_probe" {
			t.Fatalf("input=%+v", input)
		}
		return document, nil
	}), EnvironmentID: "env_1", Purpose: "direct_probe", Consumer: "terminal", AccountID: "account_1", RootPublicKey: testDescriptorRoot().Public().(ed25519.PublicKey), ControllingEndpointID: document.InitiatorEndpointID, ControlledEndpointID: document.ResponderEndpointID, ControllingCertificateFingerprint: controllingFingerprint, ControlledCertificateFingerprint: controlledFingerprint, OperationID: func(Generation) string { return document.OperationID }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Acquire(context.Background(), Generation{Attempt: 2, Network: 4}); err != nil {
		t.Fatal(err)
	}
	document.Policy.AllowedPaths = []string{"direct_quic", "relay_quic", "relay_wss"}
	if _, err := source.Acquire(context.Background(), Generation{Attempt: 2, Network: 4}); !errors.Is(err, ErrDescriptorInvalid) {
		t.Fatalf("interactive policy accepted for direct probe: %v", err)
	}
}

func TestAPIDescriptorSourceBindsRequestedWSSOnlyPolicy(t *testing.T) {
	now := time.Unix(2000, 0).UTC()
	document := peerAttemptDocument(t, now)
	document.Policy.AllowedPaths = []string{"relay_wss"}
	controllingFingerprint, controlledFingerprint := documentFingerprints(t, document)
	source, err := NewAPIDescriptorSource(APIDescriptorSourceConfig{Client: peerAttemptClientFunc(func(_ context.Context, input api.PeerAttemptInput) (api.PeerAttemptDescriptor, error) {
		if !slices.Equal(input.AllowedPaths, []string{"relay_wss"}) {
			t.Fatalf("request allowed paths=%v", input.AllowedPaths)
		}
		return document, nil
	}), EnvironmentID: "env_1", Purpose: "interactive", Consumer: "terminal", AccountID: "account_1", RootPublicKey: testDescriptorRoot().Public().(ed25519.PublicKey), ControllingEndpointID: document.InitiatorEndpointID, ControlledEndpointID: document.ResponderEndpointID, ControllingCertificateFingerprint: controllingFingerprint, ControlledCertificateFingerprint: controlledFingerprint, AllowedPaths: []string{"relay_wss"}, OperationID: func(Generation) string { return document.OperationID }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Acquire(context.Background(), Generation{Attempt: 2, Network: 4}); err != nil {
		t.Fatal(err)
	}
	document.Policy.AllowedPaths = []string{"direct_quic", "relay_quic", "relay_wss"}
	if _, err := source.Acquire(context.Background(), Generation{Attempt: 2, Network: 4}); !errors.Is(err, ErrDescriptorInvalid) {
		t.Fatalf("broadened descriptor error=%v", err)
	}
}

func descriptorSourceForTest(t *testing.T, client peerAttemptClientFunc) *APIDescriptorSource {
	t.Helper()
	document := peerAttemptDocument(t, time.Unix(2000, 0).UTC())
	document.OperationID = "peer-operation-0123456789"
	controllingFingerprint, controlledFingerprint := documentFingerprints(t, document)
	source, err := NewAPIDescriptorSource(APIDescriptorSourceConfig{Client: client, EnvironmentID: "env_1", Purpose: "interactive", Consumer: "terminal", AccountID: "account_1", RootPublicKey: testDescriptorRoot().Public().(ed25519.PublicKey), ControllingEndpointID: document.InitiatorEndpointID, ControlledEndpointID: document.ResponderEndpointID, ControllingCertificateFingerprint: controllingFingerprint, ControlledCertificateFingerprint: controlledFingerprint, OperationID: func(Generation) string { return "peer-operation-0123456789" }})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func documentFingerprints(t *testing.T, document api.PeerAttemptDescriptor) (string, string) {
	t.Helper()
	values := make([]string, 0, 2)
	for _, certificate := range document.EndpointCertificates {
		raw, err := base64.RawURLEncoding.DecodeString(certificate.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		values = append(values, hex.EncodeToString(digest[:]))
	}
	return values[0], values[1]
}

func peerAttemptDocument(t *testing.T, now time.Time) api.PeerAttemptDescriptor {
	t.Helper()
	root := testDescriptorRoot()
	certificate := func(endpoint string, role endpointidentity.Role, seed byte) string {
		var noise [32]byte
		for index := range noise {
			noise[index] = seed
		}
		value, err := endpointidentity.Sign(root, endpointidentity.Claims{AccountID: "account_1", Role: role, EndpointID: endpoint, NoisePublicKey: noise, QUICPublicKey: ed25519.NewKeyFromSeed([]byte(strings.Repeat(string(seed+1), ed25519.SeedSize))).Public().(ed25519.PublicKey), Generation: 1, Serial: uint64(seed), IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := value.MarshalBinary()
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	var result api.PeerAttemptDescriptor
	result.Version, result.IntentID, result.EnvironmentID, result.Purpose = 1, "psi_0123456789abcdef", "env_1", "interactive"
	result.Consumer = "terminal"
	result.AccountID, result.DeviceID, result.OperationID = "account_1", "endpoint_cli", "peer-operation-2-4"
	result.InitiatorEndpointID, result.ResponderEndpointID, result.Role = "endpoint_cli", "endpoint_machine", "controlling"
	result.AttemptGeneration, result.NetworkGeneration, result.HostGeneration, result.AuthorizationGeneration, result.IssuedAt, result.ExpiresAt = 2, 4, 1, 7, now, now.Add(5*time.Minute)
	result.EndpointCertificates = []api.PeerAttemptCertificate{{EndpointID: result.InitiatorEndpointID, Certificate: certificate(result.InitiatorEndpointID, endpointidentity.RoleCLI, 1)}, {EndpointID: result.ResponderEndpointID, Certificate: certificate(result.ResponderEndpointID, endpointidentity.RoleMachine, 2)}}
	result.Direct.ICEUfrag, result.Direct.ICEPassword, result.Direct.STUNURLs = "abcdefghijklmnop", "abcdefghijklmnopqrstuvwxyzABCDEF", []string{"stun:stun.example.test:3478"}
	result.Signaling.URL, result.Signaling.Credential, result.Signaling.Subprotocol = "wss://signal.example.test/v1/peer-signaling", "header.payload.signature", "paperboat.peer-signaling.v1"
	result.Relays = []api.PeerAttemptRelay{{Region: "development", RouteGeneration: 1, QUICURL: "https://signal.example.test/v1/peer-relay", WSSURL: "wss://signal.example.test/v1/peer-relay", RouteToken: "header.payload.signature", PMTUToken: "pmtu.payload.signature", PMTUURL: "udp://signal.example.test:3478", ExpiresAt: result.ExpiresAt}}
	result.Policy.AllowedPaths = []string{"direct_quic", "relay_quic", "relay_wss"}
	result.Policy.RelayDeadlineMS, result.Policy.HealthIntervalMS, result.Policy.MaxCandidates = 5000, 15000, 32
	return result
}

func testDescriptorRoot() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte(strings.Repeat("r", ed25519.SeedSize)))
}
