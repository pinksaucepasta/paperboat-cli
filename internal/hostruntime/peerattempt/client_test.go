package peerattempt

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	identitystore "github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/machinecontrol"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

type credentialContractStub struct{}

func (credentialContractStub) Token(context.Context) (string, error) {
	return strings.Repeat("t", 32), nil
}
func (credentialContractStub) Proof(context.Context, string, string, string, []byte) ([]byte, error) {
	return []byte("proof"), nil
}

func TestNewAcceptsHostedCredentialContract(t *testing.T) {
	client, err := New(Config{ControlURL: "https://api.example.test", StateRoot: t.TempDir()}, credentialContractStub{})
	if err != nil || client == nil {
		t.Fatalf("client=%v err=%v", client, err)
	}
}

func TestRejectRevokesDeliveredDescriptor(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/peer-attempts/intent_01/7" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("t", 32) || r.Header.Get("X-Paperboat-Machine-Proof") == "" || r.Header.Get("Idempotency-Key") == "" {
			t.Fatalf("method=%s path=%s headers=%v", r.Method, r.URL.Path, r.Header)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := New(Config{ControlURL: server.URL, StateRoot: t.TempDir(), Transport: server.Client().Transport}, credentialContractStub{})
	if err != nil {
		t.Fatal(err)
	}
	err = client.Reject(context.Background(), api.PeerAttemptDescriptor{IntentID: "intent_01", AttemptGeneration: 7})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNextAuthenticatesAndValidatesControlledDescriptor(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "identity")
	store, err := identitystore.Open(identitystore.Config{StateRoot: stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	identityKey := store.Current()
	registration := identitystore.Registration{ServerURL: "https://api.example.test", MachineID: "machine_01", EnvironmentID: "env_01", PublicKeyID: identityKey.ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(identityKey.Public()), InboxPath: filepath.Join(stateRoot, "inbox"), InstallationGeneration: 3, SetupRoles: []string{"host"}, UpdatedAt: now}
	if err := store.SaveRegistration(registration); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveMachineControl(identitystore.MachineControl{MachineID: registration.MachineID, EnvironmentID: registration.EnvironmentID, InstallationGeneration: 3, Credential: strings.Repeat("t", 32), ExpiresAt: now.Add(time.Hour), KeyID: identityKey.ID}); err != nil {
		t.Fatal(err)
	}
	local, err := store.PeerEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(nil)
	localCertificate, _ := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{AccountID: "account_01", Role: endpointidentity.RoleMachine, EndpointID: registration.MachineID, NoisePublicKey: local.NoisePublicKey(), QUICPublicKey: local.QUICPublicKey(), Generation: 3, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	localRaw, _ := localCertificate.MarshalBinary()
	if err := store.SavePeerEndpointCertificate(rootPublic, localRaw, now); err != nil {
		t.Fatal(err)
	}
	var cliNoise [32]byte
	cliNoise[0] = 9
	cliPublic, _, _ := ed25519.GenerateKey(nil)
	cliCertificate, _ := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{AccountID: "account_01", Role: endpointidentity.RoleCLI, EndpointID: "cli_01", NoisePublicKey: cliNoise, QUICPublicKey: cliPublic, Generation: 1, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	cliRaw, _ := cliCertificate.MarshalBinary()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/machine-peer-attempts/next" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("t", 32) || r.Header.Get("X-Paperboat-Machine-Proof") == "" {
			t.Fatalf("path=%s headers=%v", r.URL.Path, r.Header)
		}
		var body struct {
			OperationID string `json:"operation_id"`
			Generation  uint64 `json:"generation"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Generation != 3 || body.OperationID != pollOperationID("machine_01", 3) {
			t.Fatalf("body=%+v", body)
		}
		descriptor := api.PeerAttemptDescriptor{Version: 1, AccountID: "account_01", DeviceID: "cli_01", OperationID: "operation_peer_attempt_01", IntentID: "psi_0123456789abcdef", EnvironmentID: "env_01", Purpose: "interactive", Consumer: "terminal", InitiatorEndpointID: "cli_01", ResponderEndpointID: "machine_01", Role: "controlled", AttemptGeneration: 1, NetworkGeneration: 1, HostGeneration: 3, AuthorizationGeneration: 4, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), EndpointCertificates: []api.PeerAttemptCertificate{{EndpointID: "cli_01", Certificate: base64.RawURLEncoding.EncodeToString(cliRaw)}, {EndpointID: "machine_01", Certificate: base64.RawURLEncoding.EncodeToString(localRaw)}}}
		descriptor.Direct.ICEUfrag, descriptor.Direct.ICEPassword, descriptor.Direct.STUNURLs = "abcdefghijklmnop", "abcdefghijklmnopqrstuvwxyzABCDEF", []string{"stun:stun.example.test:3478"}
		descriptor.Signaling.URL, descriptor.Signaling.Credential, descriptor.Signaling.Subprotocol = "wss://relay.example.test/v1/peer-signaling", "signal.token.signature", "paperboat.peer-signaling.v1"
		descriptor.Relays = []api.PeerAttemptRelay{{Region: "region_01", RouteGeneration: 1, QUICURL: "https://relay.example.test/v1/peer-relay", WSSURL: "wss://relay.example.test/v1/peer-relay", RouteToken: "relay.token.signature", PMTUToken: "pmtu.token.signature", PMTUURL: "udp://relay.example.test:3478", ExpiresAt: descriptor.ExpiresAt}}
		descriptor.Policy.AllowedPaths = []string{"relay_wss"}
		descriptor.Policy.RelayDeadlineMS, descriptor.Policy.HealthIntervalMS, descriptor.Policy.MaxCandidates = 5000, 15000, 32
		_ = json.NewEncoder(w).Encode(map[string]any{"data": descriptor})
	}))
	defer server.Close()
	control, err := machinecontrol.NewSource(machinecontrol.Config{ControlURL: server.URL, StateRoot: stateRoot, Transport: server.Client().Transport, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(Config{ControlURL: server.URL, StateRoot: stateRoot, Transport: server.Client().Transport, Clock: func() time.Time { return now }}, control)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := client.Next(context.Background())
	if err != nil || descriptor.Role != "controlled" || descriptor.ResponderEndpointID != "machine_01" || !validAllowedPaths(descriptor.Purpose, descriptor.Policy.AllowedPaths) {
		t.Fatalf("descriptor=%+v err=%v", descriptor, err)
	}
	localFingerprint := sha256.Sum256(localRaw)
	if hex.EncodeToString(localFingerprint[:]) == "" {
		t.Fatal("empty local fingerprint")
	}
}

func TestValidAllowedPathsFailsClosed(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		purpose string
		paths   []string
		valid   bool
	}{
		{"interactive", []string{"direct_quic", "relay_quic", "relay_wss"}, true},
		{"interactive", []string{"direct_quic", "relay_quic"}, true},
		{"interactive", []string{"direct_quic"}, true},
		{"interactive", []string{"relay_quic"}, true},
		{"interactive", []string{"relay_quic", "relay_wss"}, true},
		{"interactive", []string{"relay_wss"}, true},
		{"interactive", []string{"relay_wss", "direct_quic"}, false},
		{"interactive", []string{"direct_quic", "relay_wss"}, false},
		{"interactive", []string{"relay_wss", "relay_wss"}, false},
		{"interactive", []string{"unknown"}, false},
		{"interactive", nil, false},
		{"direct_probe", []string{"direct_quic"}, true},
		{"direct_probe", []string{"direct_quic", "relay_quic", "relay_wss"}, false},
		{"private_preview", []string{"direct_quic"}, true},
		{"private_preview", []string{"relay_quic"}, false},
		{"private_preview", []string{"direct_quic", "relay_quic", "relay_wss"}, false},
	} {
		if got := validAllowedPaths(test.purpose, test.paths); got != test.valid {
			t.Fatalf("purpose=%q paths=%v valid=%t want=%t", test.purpose, test.paths, got, test.valid)
		}
	}
}
