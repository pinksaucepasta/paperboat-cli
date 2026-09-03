//go:build darwin || linux

package runtime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	clientapi "github.com/pinksaucepasta/paperboat/internal/api"
	clientconfig "github.com/pinksaucepasta/paperboat/internal/config"
	runtimeconfig "github.com/pinksaucepasta/paperboat/internal/hostruntime/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/envinject"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/environmentenrollment"
	runtimeidentity "github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	peeridentityenrollment "github.com/pinksaucepasta/paperboat/internal/hostruntime/peeridentity"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/peerrelay"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/server"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkcheck"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/signaling"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/streamauth"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
	"golang.org/x/crypto/ssh"
)

type testTokenSource struct{}

type clientPeerAttemptSource struct{}

func (*clientPeerAttemptSource) Next(context.Context) (clientapi.PeerAttemptDescriptor, error) {
	return clientapi.PeerAttemptDescriptor{}, context.Canceled
}

type runtimeObservationConnector struct{}

type peerEnrollmentSequence struct {
	errors []error
	calls  int
}

func (s *peerEnrollmentSequence) Ensure(context.Context) error {
	s.calls++
	if len(s.errors) == 0 {
		return nil
	}
	err := s.errors[0]
	s.errors = s.errors[1:]
	return err
}

func (runtimeObservationConnector) Status() connector.Status {
	return connector.Status{Connected: true, Generation: 2}
}

func (testTokenSource) Token(context.Context) (string, error) { return "helper-identity", nil }

func TestProductionClientPeerServiceBindsCompleteClientTransport(t *testing.T) {
	root := t.TempDir()
	attempts := &clientPeerAttemptSource{}
	networkChanges := &networkChangeService{}
	signalingSubstrate := &signaling.SubstrateManager{}
	transferKeys, err := transfercrypto.NewKeyVault(clientconfig.FileSecretStore{Dir: filepath.Join(root, "transfer-keys")})
	if err != nil {
		t.Fatal(err)
	}
	directNetwork := &directNetworkProxy{}
	transport := http.DefaultTransport
	var captured peerrelay.Config
	var observedRegion string
	service, err := newProductionClientPeerService(productionClientPeerDependencies{
		attempts:            attempts,
		networkChanges:      networkChanges,
		signalingSubstrate:  signalingSubstrate,
		stateRoot:           root,
		transport:           transport,
		authorizer:          func(string) (server.Authorizer, error) { return hostAuthorizer{}, nil },
		transferKeys:        transferKeys,
		observeRelaySuccess: func(region string) { observedRegion = region },
		directNetwork:       directNetwork,
		build: func(config peerrelay.Config) (*peerrelay.Service, error) {
			captured = config
			return peerrelay.New(config)
		},
	}, func(net.Conn) error { return nil }, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	if captured.Source != attempts || captured.Fingerprints != networkChanges || captured.SocketMapping != networkChanges {
		t.Fatal("production Client peer service did not bind attempts and network-change authorities")
	}
	if captured.SignalingSubstrate != signalingSubstrate || captured.TransferKeys != transferKeys {
		t.Fatal("production Client peer service did not bind signaling and transfer-key authorities")
	}
	if captured.HTTPClient == nil || captured.HTTPClient.Transport != transport || captured.TLS == nil || captured.TLS.MinVersion != tls.VersionTLS13 {
		t.Fatal("production Client peer service did not bind its authenticated transport contract")
	}
	if captured.Serve == nil || captured.ServePreview == nil || captured.ServeTransfer == nil || captured.AuthorizeStream == nil || captured.ServeStream == nil {
		t.Fatal("production Client peer service omitted a required serving contract")
	}
	captured.ObserveRelaySuccess("bom")
	if observedRegion != "bom" {
		t.Fatalf("observed relay region = %q, want bom", observedRegion)
	}
	if err := captured.ServeStream(t.Context(), streamauth.Header{Consumer: "terminal"}, nil); !errors.Is(err, peerrelay.ErrInvalid) {
		t.Fatalf("non-preview stream error = %v, want peerrelay.ErrInvalid", err)
	}
	previewServer, previewClient := net.Pipe()
	_ = previewClient.Close()
	if err := captured.ServeStream(t.Context(), streamauth.Header{Consumer: "private_preview"}, previewServer); errors.Is(err, peerrelay.ErrInvalid) {
		t.Fatalf("private preview was rejected by Client dispatch: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- captured.ServeTransfer(t.Context(), serverConn) }()
	request, err := http.NewRequest(http.MethodGet, "http://machine/v1/file-transfers/id", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(clientConn); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientConn), request)
	if err != nil || response.StatusCode != http.StatusNoContent {
		t.Fatalf("transfer response=%v error=%v", response, err)
	}
	_ = response.Body.Close()
	_ = clientConn.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Client transfer server did not stop after stream close")
	}

	directNetwork.mu.RLock()
	target := directNetwork.target
	directNetwork.mu.RUnlock()
	peerService, ok := service.(*peerrelay.Service)
	if !ok || target != peerService {
		t.Fatal("production Client peer service was not installed as direct-network recovery target")
	}
}

type testProofSource struct{ body []byte }

func (p *testProofSource) Proof(_ context.Context, _ string, method, path string, body []byte) ([]byte, error) {
	if method != http.MethodPost || path != "/v1/runtime-observations" {
		return nil, errors.New("wrong proof target")
	}
	p.body = append([]byte(nil), body...)
	return []byte("proof"), nil
}

type managedSSHTestIdentity struct {
	tokens []string
	proofs []managedSSHTestProof
}

type managedSSHTestProof struct {
	operationID string
	method      string
	path        string
	body        []byte
}

func (s *managedSSHTestIdentity) Token(context.Context) (string, error) {
	if len(s.tokens) == 0 {
		return "", errors.New("no managed SSH identity")
	}
	token := s.tokens[0]
	s.tokens = s.tokens[1:]
	return token, nil
}

func (s *managedSSHTestIdentity) Proof(_ context.Context, operationID, method, path string, body []byte) ([]byte, error) {
	s.proofs = append(s.proofs, managedSSHTestProof{operationID: operationID, method: method, path: path, body: append([]byte(nil), body...)})
	return []byte("proof-" + operationID), nil
}

type managedSSHTestClient struct {
	observedIdentity string
	observedProof    []byte
	keysIdentity     string
	keysProof        []byte
}

func (c *managedSSHTestClient) ObserveManagedSSHHostKeys(_ context.Context, machineID, identity, operationID, setID string, generation, observation uint64, keys []string, proof []byte) (clientapi.ManagedSSHHostKeySet, error) {
	wantFingerprint := sha256.Sum256([]byte("host-set-one"))
	wantObserveOperation, _ := managedSSHInitialOperationIDs(runtimeidentity.Registration{MachineID: "machine_1", InstallationGeneration: 4}, 7, wantFingerprint)
	if machineID != "machine_1" || operationID != wantObserveOperation || setID != "set_1" || generation != 4 || observation != 7 || len(keys) != 1 {
		return clientapi.ManagedSSHHostKeySet{}, errors.New("wrong host-key observation")
	}
	c.observedIdentity, c.observedProof = identity, append([]byte(nil), proof...)
	return clientapi.ManagedSSHHostKeySet{State: "active"}, nil
}

func (c *managedSSHTestClient) ManagedSSHAuthorizedKeys(_ context.Context, machineID, identity string, generation uint64, proof []byte) (clientapi.ManagedSSHAuthorizedKeys, error) {
	if machineID != "machine_1" || generation != 4 {
		return clientapi.ManagedSSHAuthorizedKeys{}, errors.New("wrong authorized-key request")
	}
	c.keysIdentity, c.keysProof = identity, append([]byte(nil), proof...)
	return clientapi.ManagedSSHAuthorizedKeys{Keys: []string{"ssh-ed25519 AAAA managed"}}, nil
}

func TestManagedSSHAuthorityUsesCurrentCredentialAndExactProofBodies(t *testing.T) {
	identity := &managedSSHTestIdentity{tokens: []string{"machine-credential-1", "machine-credential-2"}}
	client := &managedSSHTestClient{}
	registration := runtimeidentity.Registration{MachineID: "machine_1", InstallationGeneration: 4}
	fingerprint := sha256.Sum256([]byte("host-set-one"))
	observeOperationID, keyOperationID := managedSSHInitialOperationIDs(registration, 7, fingerprint)
	keys, active, err := reconcileManagedSSHAuthorityWithFingerprint(t.Context(), client, identity, registration, 7, "set_1", fingerprint, []string{"ssh-ed25519 AAAA host"})
	if err != nil || !active || len(keys.Keys) != 1 {
		t.Fatalf("keys=%#v active=%t err=%v", keys, active, err)
	}
	if client.observedIdentity != "machine-credential-1" || client.keysIdentity != "machine-credential-2" || len(identity.proofs) != 2 {
		t.Fatalf("identities=%q,%q proofs=%d", client.observedIdentity, client.keysIdentity, len(identity.proofs))
	}
	var observed struct {
		SetID                 string   `json:"set_id"`
		ObservationGeneration uint64   `json:"observation_generation"`
		PublicKeys            []string `json:"public_keys"`
	}
	if json.Unmarshal(identity.proofs[0].body, &observed) != nil || observed.SetID != "set_1" || observed.ObservationGeneration != 7 || len(observed.PublicKeys) != 1 || identity.proofs[0].method != http.MethodPut || identity.proofs[0].path != "/v1/machines/machine_1/ssh-host-keys" {
		t.Fatalf("observation proof = %#v body=%s", identity.proofs[0], identity.proofs[0].body)
	}
	if string(identity.proofs[1].body) != "{}" || identity.proofs[1].method != http.MethodPost || identity.proofs[1].path != "/v1/machines/machine_1/ssh-authorized-keys" {
		t.Fatalf("authorized-key proof = %#v", identity.proofs[1])
	}
	if string(client.observedProof) != "proof-"+observeOperationID || string(client.keysProof) != "proof-"+keyOperationID {
		t.Fatalf("proofs=%q,%q", client.observedProof, client.keysProof)
	}
}

func TestManagedSSHInitialOperationIDsBindExactHostKeyFingerprint(t *testing.T) {
	registration := runtimeidentity.Registration{MachineID: "machine_1", InstallationGeneration: 4}
	first := sha256.Sum256([]byte("host-set-one"))
	second := sha256.Sum256([]byte("host-set-two"))
	observeFirst, keysFirst := managedSSHInitialOperationIDs(registration, 7, first)
	observeReplay, keysReplay := managedSSHInitialOperationIDs(registration, 7, first)
	observeSecond, keysSecond := managedSSHInitialOperationIDs(registration, 7, second)
	observeLater, keysLater := managedSSHInitialOperationIDs(registration, 8, first)
	if observeFirst != observeReplay || keysFirst != keysReplay {
		t.Fatalf("same fingerprint did not produce stable operation IDs: %q/%q vs %q/%q", observeFirst, keysFirst, observeReplay, keysReplay)
	}
	if observeFirst == observeSecond || keysFirst == keysSecond {
		t.Fatalf("different fingerprints reused operation IDs: %q/%q vs %q/%q", observeFirst, keysFirst, observeSecond, keysSecond)
	}
	if observeFirst == observeLater || keysFirst == keysLater {
		t.Fatalf("different observation generations reused operation IDs: %q/%q vs %q/%q", observeFirst, keysFirst, observeLater, keysLater)
	}
	if len(observeFirst) > 128 || len(keysFirst) > 128 {
		t.Fatalf("operation IDs exceed machine-proof bound: %d/%d", len(observeFirst), len(keysFirst))
	}
}

type rotatingManagedSSHClient struct {
	mu            sync.Mutex
	keys          [][]string
	calls         int
	hostStates    []string
	observeErrors []error
	hostCalls     int
}

func (c *rotatingManagedSSHClient) ObserveManagedSSHHostKeys(context.Context, string, string, string, string, uint64, uint64, []string, []byte) (clientapi.ManagedSSHHostKeySet, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	index := c.hostCalls
	c.hostCalls++
	if index < len(c.observeErrors) && c.observeErrors[index] != nil {
		return clientapi.ManagedSSHHostKeySet{}, c.observeErrors[index]
	}
	state := "active"
	if len(c.hostStates) > 0 {
		if index >= len(c.hostStates) {
			index = len(c.hostStates) - 1
		}
		state = c.hostStates[index]
	}
	return clientapi.ManagedSSHHostKeySet{State: state}, nil
}

func managedSSHTestPublicKey(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPublic)))
}

func managedSSHRuntimeTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	return home
}

func (c *rotatingManagedSSHClient) ManagedSSHAuthorizedKeys(context.Context, string, string, uint64, []byte) (clientapi.ManagedSSHAuthorizedKeys, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	index := c.calls
	if index >= len(c.keys) {
		index = len(c.keys) - 1
	}
	c.calls++
	return clientapi.ManagedSSHAuthorizedKeys{Keys: append([]string(nil), c.keys[index]...)}, nil
}

type refreshingManagedSSHIdentity struct {
	mu         sync.Mutex
	operations []string
}

func (s *refreshingManagedSSHIdentity) Token(context.Context) (string, error) {
	return "machine-credential", nil
}
func (s *refreshingManagedSSHIdentity) Proof(_ context.Context, operationID, _, _ string, _ []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.operations = append(s.operations, operationID)
	return []byte("proof-" + operationID), nil
}

func TestManagedSSHKeyReconcilerConvergesAddAndRevocation(t *testing.T) {
	key := managedSSHTestPublicKey(t)
	home := managedSSHRuntimeTestHome(t)
	client := &rotatingManagedSSHClient{keys: [][]string{{key}, nil}}
	identity := &refreshingManagedSSHIdentity{}
	service := &managedSSHKeyReconciler{client: client, identity: identity, registration: runtimeidentity.Registration{MachineID: "machine_1", InstallationGeneration: 4}, workerGeneration: 9, setID: "set_1", publicKeys: []string{"ssh-ed25519 AAAA host"}, home: home, ownerUID: uint32(os.Getuid()), interval: 10 * time.Millisecond, timeout: time.Second}
	if err := service.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Shutdown(context.Background()) })
	path := filepath.Join(home, ".ssh", "authorized_keys")
	added, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(added, []byte(key)) {
		t.Fatalf("initial authorized_keys=%q error=%v", added, err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		updated, readErr := os.ReadFile(path)
		if readErr == nil && !bytes.Contains(updated, []byte(key)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("managed key was not revoked: %q error=%v", updated, readErr)
		}
		time.Sleep(5 * time.Millisecond)
	}
	identity.mu.Lock()
	operations := append([]string(nil), identity.operations...)
	identity.mu.Unlock()
	if len(operations) < 4 || operations[0] == operations[2] || !strings.Contains(operations[0], "-machine_1-4-9-refresh-") {
		t.Fatalf("proof operations=%v", operations)
	}
}

func TestManagedSSHKeyReconcilerActivatesPromotedHostWithoutRestart(t *testing.T) {
	key := managedSSHTestPublicKey(t)
	home := managedSSHRuntimeTestHome(t)
	client := &rotatingManagedSSHClient{hostStates: []string{"pending", "active"}, keys: [][]string{{key}}}
	identity := &refreshingManagedSSHIdentity{}
	service := &managedSSHKeyReconciler{client: client, identity: identity, registration: runtimeidentity.Registration{MachineID: "machine_1", InstallationGeneration: 4}, workerGeneration: 10, setID: "set_1", publicKeys: []string{"ssh-ed25519 AAAA host"}, home: home, ownerUID: uint32(os.Getuid()), interval: 10 * time.Millisecond, timeout: time.Second}
	if err := service.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Shutdown(context.Background()) })
	path := filepath.Join(home, ".ssh", "authorized_keys")
	initial, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) || bytes.Contains(initial, []byte(key)) {
		t.Fatalf("pending authorized_keys=%q error=%v", initial, err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		updated, readErr := os.ReadFile(path)
		if readErr == nil && bytes.Contains(updated, []byte(key)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("promoted host did not activate managed key: %q error=%v", updated, readErr)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestManagedSSHKeyReconcilerFailsClosedWhenAuthorityRefreshFails(t *testing.T) {
	key := managedSSHTestPublicKey(t)
	home := managedSSHRuntimeTestHome(t)
	client := &rotatingManagedSSHClient{keys: [][]string{{key}}, observeErrors: []error{nil, errors.New("authority unavailable")}}
	service := &managedSSHKeyReconciler{client: client, identity: &refreshingManagedSSHIdentity{}, registration: runtimeidentity.Registration{MachineID: "machine_1", InstallationGeneration: 4}, workerGeneration: 11, setID: "set_1", publicKeys: []string{"ssh-ed25519 AAAA host"}, home: home, ownerUID: uint32(os.Getuid()), interval: 10 * time.Millisecond, timeout: time.Second}
	if err := service.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Shutdown(context.Background()) })
	path := filepath.Join(home, ".ssh", "authorized_keys")
	deadline := time.Now().Add(time.Second)
	for {
		updated, readErr := os.ReadFile(path)
		if readErr == nil && !bytes.Contains(updated, []byte(key)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("managed key survived failed authority refresh: %q error=%v", updated, readErr)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestManagedSSHKeyReconcilerReportsTypedInitialAuthorityFailure(t *testing.T) {
	service := &managedSSHKeyReconciler{client: &rotatingManagedSSHClient{observeErrors: []error{errors.New("authority unavailable")}}, identity: &refreshingManagedSSHIdentity{}, registration: runtimeidentity.Registration{MachineID: "machine_1", InstallationGeneration: 4}, workerGeneration: 13, setID: "set_1", publicKeys: []string{"ssh-ed25519 AAAA host"}, home: t.TempDir(), ownerUID: uint32(os.Getuid()), interval: time.Hour, timeout: time.Second}
	if err := service.Start(t.Context()); !errors.Is(err, ErrManagedSSHUnavailable) {
		t.Fatalf("Start error=%v, want managed SSH unavailable", err)
	}
}

func TestManagedSSHKeyReconcilerRemovesManagedKeysOnShutdown(t *testing.T) {
	key := managedSSHTestPublicKey(t)
	home := managedSSHRuntimeTestHome(t)
	service := &managedSSHKeyReconciler{client: &rotatingManagedSSHClient{keys: [][]string{{key}}}, identity: &refreshingManagedSSHIdentity{}, registration: runtimeidentity.Registration{MachineID: "machine_1", InstallationGeneration: 4}, workerGeneration: 12, setID: "set_1", publicKeys: []string{"ssh-ed25519 AAAA host"}, home: home, ownerUID: uint32(os.Getuid()), interval: time.Hour, timeout: time.Second}
	if err := service.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, ".ssh", "authorized_keys")
	if installed, err := os.ReadFile(path); err != nil || !bytes.Contains(installed, []byte(key)) {
		t.Fatalf("initial authorized_keys=%q error=%v", installed, err)
	}
	if err := service.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	removed, err := os.ReadFile(path)
	if err != nil || bytes.Contains(removed, []byte(key)) {
		t.Fatalf("managed key remained after shutdown: %q error=%v", removed, err)
	}
}

func TestRuntimeObservationUsesRenewableIdentityAndExactBodyProof(t *testing.T) {
	var gotAuth, gotProof string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		gotAuth, gotProof = r.Header.Get("Authorization"), r.Header.Get("X-Paperboat-Machine-Proof")
		if r.URL.Path != "/v1/runtime-observations" || !strings.Contains(body.String(), `"environment_id":"prj_1"`) {
			t.Errorf("request path/body = %s %s", r.URL.Path, body.String())
		}
		if strings.Contains(body.String(), `"environment":`) || strings.Contains(body.String(), `"environment_injection"`) {
			t.Errorf("unattached secure ENV provider advertised capability or observation")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	proofs := &testProofSource{}
	sender := &runtimeObservationSender{endpoint: server.URL + "/v1/runtime-observations", tokens: testTokenSource{}, proofs: proofs, operationID: func() (string, error) { return "op-1", nil }, environmentID: "prj_1", machineID: "mach_1", reporterVersion: "test", client: server.Client(), environment: &envinject.Provider{}, workerGeneration: 1, osBootID: "boot-1", serviceScope: "system", connector: runtimeObservationConnector{}}
	if err := sender.Send(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer helper-identity" || gotProof != base64.RawURLEncoding.EncodeToString([]byte("proof")) {
		t.Fatalf("headers auth=%q proof=%q", gotAuth, gotProof)
	}
	if len(proofs.body) == 0 || !bytes.Contains(proofs.body, []byte(`"resource_id":"mach_1"`)) {
		t.Fatalf("proof body=%s", proofs.body)
	}
}

func TestStoredEnvironmentEndpointRemainsVerifiableAfterNetworkExpiry(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	certificate, err := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{
		AccountID: "acct_1", Role: endpointidentity.RoleMachine, EndpointID: "mach_1", Generation: 3, Serial: 1,
		NoisePublicKey: [32]byte{1}, QUICPublicKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)).Public().(ed25519.PublicKey),
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := certificate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpointidentity.Verify(raw, rootPublic, endpointidentity.Expected{Role: endpointidentity.RoleMachine, EndpointID: "mach_1", Generation: 3}, time.Now().UTC()); err == nil {
		t.Fatal("fixture PBEC is not expired")
	}
	verified, err := verifyStoredEnvironmentEndpoint(runtimeidentity.PeerEndpoint{Generation: 3, RootPublicKey: rootPublic, Certificate: raw}, "mach_1")
	if err != nil || verified.Claims.AccountID != "acct_1" {
		t.Fatalf("stored certificate=%+v error=%v", verified.Claims, err)
	}
}

func TestEnvironmentInjectionSupportsHostProfilesWithLocalKeyCustody(t *testing.T) {
	registration := runtimeidentity.Registration{SetupMode: "host", MachineID: "mach_1", InstallationGeneration: 1}
	if !environmentInjectionEligible(runtimeconfig.Hosted, registration) {
		t.Fatal("hosted host runtime did not enable ENV local key custody")
	}
	if !environmentInjectionEligible(runtimeconfig.BYOD, registration) {
		t.Fatal("BYOD host runtime did not enable ENV local key custody")
	}
	registration.SetupMode = "client"
	if environmentInjectionEligible(runtimeconfig.BYOD, registration) {
		t.Fatal("client-only machine enabled host ENV custody")
	}
}

type runtimeTestEnvironmentProcessor struct {
	variables map[string]string
}

func (p runtimeTestEnvironmentProcessor) Restore(context.Context, envinject.Cache) (envinject.Verified, error) {
	return envinject.Verified{}, nil
}

func (p runtimeTestEnvironmentProcessor) Apply(_ context.Context, cache envinject.Cache, _ envinject.Bundle) (envinject.Cache, envinject.Verified, error) {
	cache.Authority = &envinject.Cursor{Generation: 9, AuthorityID: "sha256:" + strings.Repeat("a", 64)}
	cache.GlobalManifest = &envinject.ManifestEnvelope{Version: 7, KeyEpoch: 2, ManifestID: "sha256:" + strings.Repeat("b", 64), Envelope: "ciphertext-global"}
	cache.MachineManifest = &envinject.ManifestEnvelope{Version: 4, KeyEpoch: 1, ManifestID: "sha256:" + strings.Repeat("c", 64), Envelope: "ciphertext-machine"}
	return cache, envinject.Verified{
		Authority: cache.Authority,
		Global:    &envinject.ManifestCursor{Version: 7, KeyEpoch: 2, ManifestID: cache.GlobalManifest.ManifestID},
		Machine:   &envinject.ManifestCursor{Version: 4, KeyEpoch: 1, ManifestID: cache.MachineManifest.ManifestID},
		Variables: p.variables,
		Ready:     true,
	}, nil
}

func TestRuntimeObservationAppliesEncryptedBundleAndAcknowledgesIt(t *testing.T) {
	variables := map[string]string{"GLOBAL_TOKEN": "global-secret", "MACHINE_TOKEN": "machine-secret"}
	var observations []envinject.Observation
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte("global-secret")) || bytes.Contains(body, []byte("machine-secret")) {
			t.Fatal("plaintext environment value reached the runtime request")
		}
		var request struct {
			Environment        envinject.Observation         `json:"environment"`
			RuntimeDiagnostics runtimeDiagnosticsObservation `json:"runtime_diagnostics"`
		}
		if err := json.Unmarshal(body, &request); err != nil {
			t.Fatal(err)
		}
		requestCount++
		observations = append(observations, request.Environment)
		if requestCount == 1 && slices.Contains(request.RuntimeDiagnostics.Capabilities, "environment_injection") {
			t.Fatal("unverified ENV binding advertised environment_injection")
		}
		if requestCount > 1 && !slices.Contains(request.RuntimeDiagnostics.Capabilities, "environment_injection") {
			t.Fatal("verified ENV binding omitted environment_injection")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"accepted": true,
			"environment_bundle": envinject.Bundle{
				Schema: envinject.BundleSchema,
			},
		}})
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "environment-cache.json")
	store, err := envinject.Open(context.Background(), envinject.Config{
		Path: path, HighWaterPath: filepath.Join(t.TempDir(), "environment-high-water.json"), IntegrityKey: bytes.Repeat([]byte{0x42}, 32), AllowHighWaterInitialize: true, AccountID: "acct_1", MachineID: "mach_1",
		InstallationGeneration: 1, HostKeyGeneration: 1, HostRecipientKeyID: runtimeTestHostRecipientKeyID,
		GenesisMarker: runtimeTestGenesisMarkerFor(t, path),
		Processor:     runtimeTestEnvironmentProcessor{variables: variables},
	})
	if err != nil {
		t.Fatal(err)
	}
	sender := &runtimeObservationSender{endpoint: server.URL, tokens: testTokenSource{}, proofs: &testProofSource{}, operationID: func() (string, error) { return "op-1", nil }, environmentID: "prj_1", machineID: "mach_1", reporterVersion: "test", client: server.Client(), environment: store, workerGeneration: 1, osBootID: "boot-1", serviceScope: "system", connector: runtimeObservationConnector{}}
	if err := sender.Send(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := sender.Send(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(observations) != 2 || observations[0].State != "pending" || observations[1].State != "applied" || observations[1].Global == nil || observations[1].Global.Version != 7 || observations[1].Machine == nil || observations[1].Machine.Version != 4 || observations[1].ObservationSeq != 2 {
		t.Fatalf("observations=%+v", observations)
	}
	if got, err := store.Environment(); err != nil || !reflect.DeepEqual(got, []string{"GLOBAL_TOKEN=global-secret", "MACHINE_TOKEN=machine-secret"}) {
		t.Fatalf("environment=%q err=%v", got, err)
	}
}

func TestEnvironmentBootstrapCommitsActiveBindingWithoutEnrollment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment-cache.json")
	store, err := envinject.Open(context.Background(), envinject.Config{
		Path: path, HighWaterPath: path + ".high-water", IntegrityKey: bytes.Repeat([]byte{0x42}, 32), AllowHighWaterInitialize: true,
		AccountID: "acct_1", MachineID: "mach_1", InstallationGeneration: 1, HostKeyGeneration: 1, HostRecipientKeyID: runtimeTestHostRecipientKeyID,
		GenesisMarker: runtimeTestGenesisMarkerFor(t, path), Processor: runtimeTestEnvironmentProcessor{variables: map[string]string{"TOKEN": "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(context.Background(), envinject.Bundle{Schema: envinject.BundleSchema}); err != nil {
		t.Fatal(err)
	}
	provider := &envinject.Provider{}
	if err := provider.Attach(store); err != nil {
		t.Fatal(err)
	}
	if provider.BindingState() != envinject.BindingActive {
		t.Fatalf("binding state=%d, want active", provider.BindingState())
	}
	ready := make(chan struct{})
	close(ready)
	ensureCalls, commitCalls := 0, 0
	bootstrap := newEnvironmentBootstrapService(provider, func(context.Context) (*envinject.Store, error) {
		return nil, errors.New("unexpected store initialization")
	}, time.Millisecond)
	bootstrap.store = store
	bootstrap.ensure = func(context.Context) error {
		ensureCalls++
		return environmentenrollment.ErrPending
	}
	bootstrap.commit = func(context.Context) error {
		commitCalls++
		return nil
	}
	bootstrap.observationReady = ready
	if err := bootstrap.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-bootstrap.done:
	case <-time.After(time.Second):
		t.Fatal("environment bootstrap did not finish after active binding reconciliation")
	}
	if ensureCalls != 0 || commitCalls != 1 {
		t.Fatalf("ensure calls=%d commit calls=%d", ensureCalls, commitCalls)
	}
	if err := bootstrap.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeObservationIncludesMonotonicMedianRelayLatency(t *testing.T) {
	now := time.Now().UTC()
	cache := networkcheck.NewRegionalCache()
	for index, rtt := range []time.Duration{30, 10, 20} {
		if err := cache.Record("fsn1", rtt*time.Millisecond, now.Add(time.Duration(index)*time.Nanosecond)); err != nil {
			t.Fatal(err)
		}
	}
	var generations []uint64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RelayLatency *runtimeRelayLatencyObservation `json:"relay_latency"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RelayLatency == nil || len(body.RelayLatency.Samples) != 1 || body.RelayLatency.Samples[0].RTTMS != 20 {
			t.Fatalf("relay latency=%#v err=%v", body.RelayLatency, err)
		}
		generations = append(generations, body.RelayLatency.Generation)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	sender := &runtimeObservationSender{endpoint: server.URL, tokens: testTokenSource{}, proofs: &testProofSource{}, operationID: func() (string, error) { return "op-1", nil }, environmentID: "prj_1", machineID: "mach_1", reporterVersion: "test", client: server.Client(), workerGeneration: 3, osBootID: "boot", serviceScope: "system", connector: runtimeObservationConnector{}, relayLatency: cache}
	if err := sender.Send(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := sender.Send(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(generations, []uint64{1, 2}) {
		t.Fatalf("generations=%v", generations)
	}
}

func TestCurrentRelayRegionTracksOnlySuccessfulNonEmptyRegions(t *testing.T) {
	state := &currentRelayRegion{}
	state.Observe("")
	if got := state.Current(); got != "" {
		t.Fatalf("empty observation changed current region to %q", got)
	}
	state.Observe("fsn1")
	state.Observe("")
	if got := state.Current(); got != "fsn1" {
		t.Fatalf("current region=%q want fsn1", got)
	}
	state.Observe("hel1")
	if got := state.Current(); got != "hel1" {
		t.Fatalf("current region=%q want hel1", got)
	}
}

func TestProductionHelperRequiresHTTPSControl(t *testing.T) {
	base := map[string]string{"PAPERBOAT_RUNTIME_STATE_ROOT": filepath.Join(t.TempDir(), "state")}
	base["PAPERBOAT_RUNTIME_PROFILE"] = "byod"
	base["PAPERBOAT_WORKSPACE_ROOT"] = t.TempDir()
	base["PAPERBOAT_CONTROL_URL"] = "http://control.example.test"
	base["PAPERBOAT_MACHINE_ID"] = "um_1"
	if _, err := NewProductionHost(context.Background(), "test", func(name string) string { return base[name] }); !errors.Is(err, ErrProductionInvalid) {
		t.Fatalf("byod control error=%v", err)
	}
	base["PAPERBOAT_RUNTIME_PROFILE"] = "hosted"
	base["PAPERBOAT_WORKSPACE"] = filepath.Join(t.TempDir(), "volume")
	base["PAPERBOAT_PROJECT_ID"] = "prj_1"
	base["PAPERBOAT_REPOSITORY_URL"] = "https://github.com/paperboat/example.git"
	base["PAPERBOAT_CONTROL_URL"] = "http://control.example.test"
	if _, err := NewProductionHost(context.Background(), "test", func(name string) string { return base[name] }); !errors.Is(err, ErrProductionInvalid) {
		t.Fatalf("control error=%v", err)
	}
}

func TestInstalledHostModeOverridesClientRegistrationDuringUpgrade(t *testing.T) {
	if shouldRunClientCoordinator("client", "host") {
		t.Fatal("host installation started the client coordinator")
	}
	if !shouldRunClientCoordinator("client", "client") {
		t.Fatal("client installation did not start the client coordinator")
	}
	if shouldRunClientCoordinator("host", "host") {
		t.Fatal("host registration started the client coordinator")
	}
	if shouldRunClientCoordinator("receive", "client") {
		t.Fatal("retired receive registration started the client coordinator")
	}
}

func TestValidatedBYODShellRequiresExecutableAbsoluteFile(t *testing.T) {
	shell := filepath.Join(t.TempDir(), "shell")
	if err := os.WriteFile(shell, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err := validatedBYODShell(shell); err != nil || got != shell {
		t.Fatalf("shell=%q err=%v", got, err)
	}
	for _, invalid := range []string{"relative", filepath.Join(t.TempDir(), "missing")} {
		if _, err := validatedBYODShell(invalid); !errors.Is(err, ErrProductionInvalid) {
			t.Fatalf("invalid shell %q err=%v", invalid, err)
		}
	}
	wantDefault, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := validatedBYODShell(""); err != nil || got != wantDefault {
		t.Fatalf("fallback shell=%q err=%v", got, err)
	}
}

func TestValidateBYODWorkspaceRejectsNonCanonicalAndSymlinkRoots(t *testing.T) {
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateBYODWorkspace(root); err != nil {
		t.Fatal(err)
	}
	if err := validateBYODWorkspace(root + string(os.PathSeparator) + "."); !errors.Is(err, ErrProductionInvalid) {
		t.Fatalf("non-canonical error=%v", err)
	}
	link := filepath.Join(t.TempDir(), "workspace")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if err := validateBYODWorkspace(link); !errors.Is(err, ErrProductionInvalid) {
		t.Fatalf("symlink error=%v", err)
	}
	if err := validateBYODWorkspace("relative"); !errors.Is(err, ErrProductionInvalid) {
		t.Fatalf("relative error=%v", err)
	}
}

func TestRetryHostedControlWaitsForTransientFailure(t *testing.T) {
	attempts := 0
	started := time.Now()
	result, err := retryHostedControl(context.Background(), func(context.Context) (string, error) {
		attempts++
		if attempts == 1 {
			return "", errors.New("control plane is not ready")
		}
		return "ready", nil
	})
	if err != nil || result != "ready" || attempts != 2 || time.Since(started) < time.Second {
		t.Fatalf("result=%q err=%v attempts=%d elapsed=%s", result, err, attempts, time.Since(started))
	}
}

func TestRetryHostedControlStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	_, err := retryHostedControl(ctx, func(context.Context) (string, error) {
		attempts++
		cancel()
		return "", errors.New("unavailable")
	})
	if !errors.Is(err, context.Canceled) || attempts != 1 {
		t.Fatalf("err=%v attempts=%d", err, attempts)
	}
}

func TestWaitForPeerEnrollmentRetriesPendingUntilApproved(t *testing.T) {
	enrollment := &peerEnrollmentSequence{errors: []error{
		&peeridentityenrollment.PendingError{RequestID: "per_01", SafetyCode: "abcde-f0123"},
		peeridentityenrollment.ErrPending,
		nil,
	}}
	if err := waitForPeerEnrollment(context.Background(), enrollment, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if enrollment.calls != 3 {
		t.Fatalf("calls=%d", enrollment.calls)
	}
}

func TestWaitForPeerEnrollmentStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	enrollment := &peerEnrollmentSequence{errors: []error{peeridentityenrollment.ErrPending}}
	if err := waitForPeerEnrollment(ctx, enrollment, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if enrollment.calls != 1 {
		t.Fatalf("calls=%d", enrollment.calls)
	}
}

func TestPeerEnrollmentRuntimeServicePersistsApprovalAfterStartup(t *testing.T) {
	enrollment := &peerEnrollmentSequence{errors: []error{
		peeridentityenrollment.ErrPending,
		nil,
	}}
	service := newPeerEnrollmentRuntimeService(enrollment, time.Millisecond)
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-service.done:
	case <-time.After(time.Second):
		t.Fatal("peer enrollment runtime service did not observe approval")
	}
	if enrollment.calls != 2 {
		t.Fatalf("calls=%d", enrollment.calls)
	}
	if err := service.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestProductionConnectorTransportDefaultsToAuto(t *testing.T) {
	for _, value := range []string{"", "  "} {
		if got := productionConnectorTransport(value); got != connector.Auto {
			t.Fatalf("transport(%q) = %q", value, got)
		}
	}
	if got := productionConnectorTransport("quic"); got != connector.QUIC {
		t.Fatalf("explicit transport = %q", got)
	}
}
