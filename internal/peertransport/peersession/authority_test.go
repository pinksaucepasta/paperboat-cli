package peersession

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
)

func TestAuthoritiesDeriveMatchingSessionAndStreams(t *testing.T) {
	t.Parallel()

	descriptor := api.PeerAttemptDescriptor{
		Version:                 1,
		AccountID:               "account_01",
		DeviceID:                "cli_01",
		OperationID:             "operation_01",
		IntentID:                "intent_01",
		Purpose:                 "interactive",
		Consumer:                "terminal",
		InitiatorEndpointID:     "cli_01",
		ResponderEndpointID:     "machine_01",
		Role:                    "controlling",
		AttemptGeneration:       2,
		HostGeneration:          3,
		AuthorizationGeneration: 4,
	}
	cliKey, cliCertificate := endpointForTest(t, descriptor.AccountID, descriptor.InitiatorEndpointID, endpointidentity.RoleCLI, 1)
	machineKey, machineCertificate := endpointForTest(t, descriptor.AccountID, descriptor.ResponderEndpointID, endpointidentity.RoleMachine, descriptor.HostGeneration)

	controlling, err := New(Config{Descriptor: descriptor, LocalCertificate: cliCertificate, PeerCertificate: machineCertificate, LocalNoisePrivate: cliKey, Consumer: "terminal"})
	if err != nil {
		t.Fatal(err)
	}
	descriptor.Role = "controlled"
	controlled, err := New(Config{Descriptor: descriptor, LocalCertificate: machineCertificate, PeerCertificate: cliCertificate, LocalNoisePrivate: machineKey, Consumer: "terminal"})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(controlling.Context, controlled.Context) || controlling.RouteHandle != controlled.RouteHandle || controlling.PMTUKey() != controlled.PMTUKey() || controlling.PMTUKey() == ([32]byte{}) {
		t.Fatal("peer authorities derived different session context")
	}
	if controlling.LocalEndpointID() != "cli_01" || controlling.PeerEndpointID() != "machine_01" || controlled.LocalEndpointID() != "machine_01" || controlled.PeerEndpointID() != "cli_01" {
		t.Fatal("peer authorities assigned incorrect endpoint ownership")
	}

	seen := make(map[[16]byte]string)
	for _, streamID := range []string{"native-control", "native-input", "native-output"} {
		initiator, err := controlling.Initiator(streamID)
		if err != nil {
			t.Fatal(err)
		}
		responder, err := controlled.Responder(streamID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(initiator.Context, responder.Context) || initiator.Handle != responder.Handle || initiator.PeerPublic != machineCertificate.Claims.NoisePublicKey || responder.PeerPublic != cliCertificate.Claims.NoisePublicKey {
			t.Fatalf("stream %q derived asymmetric Noise configuration", streamID)
		}
		if previous, exists := seen[initiator.Handle]; exists {
			t.Fatalf("streams %q and %q derived the same handle", previous, streamID)
		}
		seen[initiator.Handle] = streamID
	}
}

func TestLegacyAuthorityCannotDeriveReusableStreams(t *testing.T) {
	descriptor := api.PeerAttemptDescriptor{Version: 1, AccountID: "account_01", DeviceID: "cli_01", OperationID: "operation_01", IntentID: "intent_01", Purpose: "interactive", Consumer: "terminal", InitiatorEndpointID: "cli_01", ResponderEndpointID: "machine_01", Role: "controlling", AttemptGeneration: 2, HostGeneration: 3, AuthorizationGeneration: 4}
	cliKey, cliCertificate := endpointForTest(t, descriptor.AccountID, descriptor.InitiatorEndpointID, endpointidentity.RoleCLI, 1)
	_, machineCertificate := endpointForTest(t, descriptor.AccountID, descriptor.ResponderEndpointID, endpointidentity.RoleMachine, descriptor.HostGeneration)
	authority, err := New(Config{Descriptor: descriptor, LocalCertificate: cliCertificate, PeerCertificate: machineCertificate, LocalNoisePrivate: cliKey, Consumer: "terminal"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.InitiatorTransportStream(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("transport stream err=%v", err)
	}
	if _, err := authority.InitiatorStream(StreamGrant{OperationID: "operation_02", Consumer: "exec", StreamID: "stream_1", Credential: []byte("credential"), Deadline: time.Now().Add(time.Minute), MaximumBytes: 1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("application stream err=%v", err)
	}
}

func TestReusableTransportDerivesOperationScopedStreamAuthorities(t *testing.T) {
	descriptor := api.PeerAttemptDescriptor{Version: 1, AccountID: "account_01", DeviceID: "cli_01", OperationID: "bootstrap_operation", IntentID: "transport_01", Purpose: "peer_transport", Consumer: "peer_transport", InitiatorEndpointID: "cli_01", ResponderEndpointID: "machine_01", Role: "controlling", AttemptGeneration: 2, HostGeneration: 3, AuthorizationGeneration: 4}
	cliKey, cliCertificate := endpointForTest(t, descriptor.AccountID, descriptor.InitiatorEndpointID, endpointidentity.RoleCLI, 1)
	machineKey, machineCertificate := endpointForTest(t, descriptor.AccountID, descriptor.ResponderEndpointID, endpointidentity.RoleMachine, descriptor.HostGeneration)
	initiator, err := New(Config{Descriptor: descriptor, LocalCertificate: cliCertificate, PeerCertificate: machineCertificate, LocalNoisePrivate: cliKey, Consumer: "peer_transport"})
	if err != nil {
		t.Fatal(err)
	}
	descriptor.Role = "controlled"
	responder, err := New(Config{Descriptor: descriptor, LocalCertificate: machineCertificate, PeerCertificate: cliCertificate, LocalNoisePrivate: machineKey, Consumer: "peer_transport"})
	if err != nil {
		t.Fatal(err)
	}
	transportLeft, err := initiator.InitiatorTransportStream()
	if err != nil {
		t.Fatal(err)
	}
	transportRight, err := responder.ResponderTransportStream()
	if err != nil {
		t.Fatal(err)
	}
	if transportLeft.Handle != transportRight.Handle || !reflect.DeepEqual(transportLeft.Transport, transportRight.Transport) || transportLeft.Stream != (peercontext.Stream{}) || transportRight.Stream != (peercontext.Stream{}) {
		t.Fatal("transport relay authority was asymmetric")
	}
	deadline := time.Now().UTC().Add(time.Minute).Truncate(time.Second)
	grant := StreamGrant{OperationID: "operation_exec_01", Consumer: "exec", StreamID: "native-control", Credential: []byte("signed-operation-credential"), Deadline: deadline, MaximumBytes: 1 << 20}
	left, err := initiator.InitiatorStream(grant)
	if err != nil {
		t.Fatal(err)
	}
	right, err := responder.ResponderStream(grant)
	if err != nil {
		t.Fatal(err)
	}
	if left.Handle != right.Handle || !reflect.DeepEqual(left.Transport, right.Transport) || !reflect.DeepEqual(left.Stream, right.Stream) || left.Context != (peercontext.Context{}) || right.Context != (peercontext.Context{}) {
		t.Fatal("reusable stream authority was asymmetric or retained operation-bound context")
	}
	mutations := []func(*StreamGrant){
		func(v *StreamGrant) { v.OperationID = "operation_exec_02" },
		func(v *StreamGrant) { v.Consumer = "ssh" },
		func(v *StreamGrant) { v.Credential = []byte("other-credential") },
		func(v *StreamGrant) { v.Deadline = v.Deadline.Add(time.Second) },
		func(v *StreamGrant) { v.MaximumBytes++ },
	}
	for index, mutate := range mutations {
		changed := grant
		mutate(&changed)
		authority, bindErr := initiator.InitiatorStream(changed)
		if bindErr != nil || authority.Handle == left.Handle {
			t.Fatalf("mutation %d handle=%x err=%v", index, authority.Handle, bindErr)
		}
	}
}

func TestFileTransferKeyAuthorityAdmitsOnlyItsBoundedControlStream(t *testing.T) {
	descriptor := api.PeerAttemptDescriptor{Version: 1, AccountID: "account_01", DeviceID: "cli_01", OperationID: "operation_01", IntentID: "intent_01", Purpose: "file_transfer_key", Consumer: "file_transfer_key", InitiatorEndpointID: "cli_01", ResponderEndpointID: "machine_01", Role: "controlled", AttemptGeneration: 2, HostGeneration: 3, AuthorizationGeneration: 4}
	cliKey, cliCertificate := endpointForTest(t, descriptor.AccountID, descriptor.InitiatorEndpointID, endpointidentity.RoleCLI, 1)
	machineKey, machineCertificate := endpointForTest(t, descriptor.AccountID, descriptor.ResponderEndpointID, endpointidentity.RoleMachine, descriptor.HostGeneration)

	authority, err := New(Config{Descriptor: descriptor, LocalCertificate: machineCertificate, PeerCertificate: cliCertificate, LocalNoisePrivate: machineKey, Consumer: "file_transfer_key"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Responder("transfer-key-control"); err != nil {
		t.Fatalf("transfer key control stream rejected: %v", err)
	}
	for _, streamID := range []string{"native-control", "native-input", "native-output"} {
		if _, err := authority.Responder(streamID); !errors.Is(err, ErrInvalid) {
			t.Fatalf("stream %q err=%v, want ErrInvalid", streamID, err)
		}
	}
	if _, err := New(Config{Descriptor: descriptor, LocalCertificate: machineCertificate, PeerCertificate: cliCertificate, LocalNoisePrivate: machineKey, Consumer: "terminal"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("file transfer purpose with terminal consumer err=%v, want ErrInvalid", err)
	}
	descriptor.Purpose = "interactive"
	descriptor.Role = "controlling"
	if _, err := New(Config{Descriptor: descriptor, LocalCertificate: cliCertificate, PeerCertificate: machineCertificate, LocalNoisePrivate: cliKey, Consumer: "file_transfer_key"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("interactive purpose with file transfer consumer err=%v, want ErrInvalid", err)
	}
}

func TestPrivatePreviewAuthorityCannotCrossConsumerBoundary(t *testing.T) {
	descriptor := api.PeerAttemptDescriptor{Version: 1, AccountID: "account_01", DeviceID: "cli_01", OperationID: "operation_01", IntentID: "intent_01", Purpose: "private_preview", Consumer: "private_preview", InitiatorEndpointID: "cli_01", ResponderEndpointID: "machine_01", Role: "controlled", AttemptGeneration: 2, HostGeneration: 3, AuthorizationGeneration: 4}
	cliKey, cliCertificate := endpointForTest(t, descriptor.AccountID, descriptor.InitiatorEndpointID, endpointidentity.RoleCLI, 1)
	machineKey, machineCertificate := endpointForTest(t, descriptor.AccountID, descriptor.ResponderEndpointID, endpointidentity.RoleMachine, descriptor.HostGeneration)
	authority, err := New(Config{Descriptor: descriptor, LocalCertificate: machineCertificate, PeerCertificate: cliCertificate, LocalNoisePrivate: machineKey, Consumer: "private_preview"})
	if err != nil {
		t.Fatalf("private preview authority rejected: %v", err)
	}
	if _, err := authority.Responder("private-preview"); err != nil {
		t.Fatalf("private preview stream rejected: %v", err)
	}
	for _, streamID := range []string{"native-control", "native-input", "native-output", "transfer-key-control"} {
		if _, err := authority.Responder(streamID); !errors.Is(err, ErrInvalid) {
			t.Fatalf("stream %q err=%v, want ErrInvalid", streamID, err)
		}
	}
	if _, err := New(Config{Descriptor: descriptor, LocalCertificate: machineCertificate, PeerCertificate: cliCertificate, LocalNoisePrivate: machineKey, Consumer: "terminal"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("private preview purpose with terminal consumer err=%v, want ErrInvalid", err)
	}
	descriptor.Purpose = "interactive"
	descriptor.Role = "controlling"
	if _, err := New(Config{Descriptor: descriptor, LocalCertificate: cliCertificate, PeerCertificate: machineCertificate, LocalNoisePrivate: cliKey, Consumer: "private_preview"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("interactive purpose with private preview consumer err=%v, want ErrInvalid", err)
	}
}

func TestCodexAuthorityCannotCrossConsumerBoundary(t *testing.T) {
	descriptor := api.PeerAttemptDescriptor{Version: 1, AccountID: "account_01", DeviceID: "cli_01", OperationID: "operation_01", IntentID: "intent_01", Purpose: "codex", Consumer: "codex", InitiatorEndpointID: "cli_01", ResponderEndpointID: "machine_01", Role: "controlled", AttemptGeneration: 2, HostGeneration: 3, AuthorizationGeneration: 4}
	cliKey, cliCertificate := endpointForTest(t, descriptor.AccountID, descriptor.InitiatorEndpointID, endpointidentity.RoleCLI, 1)
	machineKey, machineCertificate := endpointForTest(t, descriptor.AccountID, descriptor.ResponderEndpointID, endpointidentity.RoleMachine, descriptor.HostGeneration)
	authority, err := New(Config{Descriptor: descriptor, LocalCertificate: machineCertificate, PeerCertificate: cliCertificate, LocalNoisePrivate: machineKey, Consumer: "codex"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Responder("codex-http"); err != nil {
		t.Fatalf("codex stream rejected: %v", err)
	}
	for _, streamID := range []string{"native-control", "native-input", "native-output", "private-preview", "transfer-key-control"} {
		if _, err := authority.Responder(streamID); !errors.Is(err, ErrInvalid) {
			t.Fatalf("stream %q err=%v, want ErrInvalid", streamID, err)
		}
	}
	if _, err := New(Config{Descriptor: descriptor, LocalCertificate: machineCertificate, PeerCertificate: cliCertificate, LocalNoisePrivate: machineKey, Consumer: "terminal"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("codex purpose with terminal consumer err=%v, want ErrInvalid", err)
	}
	descriptor.Purpose = "interactive"
	descriptor.Role = "controlling"
	if _, err := New(Config{Descriptor: descriptor, LocalCertificate: cliCertificate, PeerCertificate: machineCertificate, LocalNoisePrivate: cliKey, Consumer: "codex"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("interactive purpose with codex consumer err=%v, want ErrInvalid", err)
	}
}

func TestHealthProbeAuthorityAdmitsNoApplicationStream(t *testing.T) {
	descriptor := api.PeerAttemptDescriptor{Version: 1, AccountID: "account_01", DeviceID: "cli_01", OperationID: "operation_01", IntentID: "intent_01", Purpose: "health_probe", Consumer: "health_probe", InitiatorEndpointID: "cli_01", ResponderEndpointID: "machine_01", Role: "controlled", AttemptGeneration: 2, HostGeneration: 3, AuthorizationGeneration: 4}
	cliKey, cliCertificate := endpointForTest(t, descriptor.AccountID, descriptor.InitiatorEndpointID, endpointidentity.RoleCLI, 1)
	machineKey, machineCertificate := endpointForTest(t, descriptor.AccountID, descriptor.ResponderEndpointID, endpointidentity.RoleMachine, descriptor.HostGeneration)
	authority, err := New(Config{Descriptor: descriptor, LocalCertificate: machineCertificate, PeerCertificate: cliCertificate, LocalNoisePrivate: machineKey, Consumer: "health_probe"})
	if err != nil {
		t.Fatalf("health probe authority rejected: %v", err)
	}
	if _, err := authority.Responder("native-health"); err != nil {
		t.Fatalf("native health stream rejected: %v", err)
	}
	for _, streamID := range []string{"native-control", "native-input", "native-output", "private-preview", "transfer-key-control"} {
		if _, err := authority.Responder(streamID); !errors.Is(err, ErrInvalid) {
			t.Fatalf("stream %q err=%v, want ErrInvalid", streamID, err)
		}
	}
	if _, err := New(Config{Descriptor: descriptor, LocalCertificate: machineCertificate, PeerCertificate: cliCertificate, LocalNoisePrivate: machineKey, Consumer: "terminal"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("health probe purpose with terminal consumer err=%v, want ErrInvalid", err)
	}
	descriptor.Purpose = "interactive"
	descriptor.Role = "controlling"
	if _, err := New(Config{Descriptor: descriptor, LocalCertificate: cliCertificate, PeerCertificate: machineCertificate, LocalNoisePrivate: cliKey, Consumer: "health_probe"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("interactive purpose with health probe consumer err=%v, want ErrInvalid", err)
	}
}

func endpointForTest(t *testing.T, accountID, endpointID string, role endpointidentity.Role, generation uint64) ([32]byte, endpointidentity.Certificate) {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	_ = rootPublic
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, quicPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var noisePublic [32]byte
	copy(noisePublic[:], key.PublicKey().Bytes())
	var noisePrivate [32]byte
	copy(noisePrivate[:], key.Bytes())
	now := time.Now().UTC().Truncate(time.Second)
	certificate, err := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{AccountID: accountID, Role: role, EndpointID: endpointID, NoisePublicKey: noisePublic, QUICPublicKey: quicPrivate.Public().(ed25519.PublicKey), Generation: generation, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return noisePrivate, certificate
}
