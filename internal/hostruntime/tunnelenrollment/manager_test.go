package tunnelenrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type testAuth struct {
	mu    sync.Mutex
	calls []string
}

func (a *testAuth) Token(context.Context) (string, error) { return strings.Repeat("m", 48), nil }
func (a *testAuth) Proof(_ context.Context, operation, method, path string, body []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, operation+" "+method+" "+path)
	digest := sha256.Sum256(append([]byte(operation+method+path), body...))
	return digest[:], nil
}

type testActivator struct {
	calls int
	err   error
	input ActivationRequest
}

func (a *testActivator) Activate(_ context.Context, in ActivationRequest) (Projection, error) {
	a.calls++
	a.input = in
	if a.err != nil {
		return Projection{}, a.err
	}
	if in.CredentialGeneration == 0 {
		in.CredentialGeneration = 1
	}
	now := time.Now().UTC()
	return Projection{Schema: Schema, Kind: "tunnel_connector", TunnelID: in.TunnelID, HostID: in.HostID, ConnectorID: in.ConnectorID, OperationID: in.OperationID, State: "ready", CredentialReference: in.CredentialReference, CredentialGeneration: in.CredentialGeneration, ReadyAt: &now}, nil
}

func TestManagerIssueExchangeActivateRestartAndNoSecretJournal(t *testing.T) {
	now := time.Now().UTC()
	var mu sync.Mutex
	issueCalls, exchangeCalls := 0, 0
	var seenToken string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("m", 48) || r.Header.Get("X-Paperboat-Machine-Proof") == "" || r.Header.Get("Idempotency-Key") == "" {
			t.Errorf("missing auth headers")
		}
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v1/tunnels/tunnel_01/connectors/enrollments":
			issueCalls++
			seenToken = "pbce_" + strings.Repeat("t", 48)
			w.WriteHeader(http.StatusCreated)
			writeEnvelope(t, w, serverEnrollment{Schema: "paperboat.preview-tunnel/v1", Kind: "connector_enrollment", ID: "enrollment_01", TunnelID: "tunnel_01", HostID: "host_01", Token: seenToken, ExpiresAt: now.Add(time.Minute), Capabilities: []string{"connector-v1"}})
		case "/v1/tunnels/tunnel_01/connectors/enrollments/exchange":
			exchangeCalls++
			raw, _ := io.ReadAll(r.Body)
			if !bytes.Contains(raw, []byte(seenToken)) {
				t.Error("exchange did not consume exact token")
			}
			w.WriteHeader(http.StatusAccepted)
			writeEnvelope(t, w, testServerActivation(now, "tunnel_01", "connector_01", "operation_01"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	store, err := NewFileCredentialStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	activator := &testActivator{}
	manager, err := NewManager(ManagerConfig{ControlURL: server.URL, HostID: "host_01", Auth: &testAuth{}, Transport: server.Client().Transport, Credentials: store, Activator: activator, ControlToken: "local-token"})
	if err != nil {
		t.Fatal(err)
	}
	projection, err := manager.Enroll(context.Background(), "tunnel_01", "local-request-01")
	if err != nil {
		t.Fatal(err)
	}
	if !projection.valid() || activator.calls != 1 || activator.input.AccountID != "account_01" || activator.input.CredentialGeneration != 3 || activator.input.ProcessGeneration != 2 {
		t.Fatalf("projection=%+v calls=%d", projection, activator.calls)
	}
	journalBytes, err := os.ReadFile(filepath.Join(store.root, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	credentials, _ := os.ReadDir(filepath.Join(store.root, "credentials"))
	if bytes.Contains(journalBytes, []byte(seenToken)) || bytes.Contains(journalBytes, []byte("private_key")) || bytes.Contains(journalBytes, []byte("seed")) || len(credentials) != 1 {
		t.Fatalf("unsafe journal=%s credentials=%d", journalBytes, len(credentials))
	}
	restarted, err := NewManager(ManagerConfig{ControlURL: server.URL, HostID: "host_01", Auth: &testAuth{}, Transport: server.Client().Transport, Credentials: store, Activator: &testActivator{}, ControlToken: "local-token"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := restarted.Enroll(context.Background(), "tunnel_01", "different-local-retry")
	if err != nil || again.ConnectorID != projection.ConnectorID {
		t.Fatalf("restart=%+v err=%v", again, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if issueCalls != 1 || exchangeCalls != 1 {
		t.Fatalf("calls issue=%d exchange=%d", issueCalls, exchangeCalls)
	}
}

func TestManagerResumeReattachesExactDurableActivationWithoutServerMutation(t *testing.T) {
	now := time.Now().UTC()
	serverCalls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalls++
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/exchange") {
			w.WriteHeader(http.StatusAccepted)
			writeEnvelope(t, w, testServerActivation(now, "tunnel_resume_01", "connector_resume_01", "operation_resume_01"))
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeEnvelope(t, w, serverEnrollment{Schema: "paperboat.preview-tunnel/v1", Kind: "connector_enrollment", ID: "enrollment_resume_01", TunnelID: "tunnel_resume_01", HostID: "host_01", Token: "pbce_" + strings.Repeat("r", 48), ExpiresAt: now.Add(time.Minute)})
	}))
	defer server.Close()
	store, err := NewFileCredentialStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	initial := &testActivator{}
	manager, err := NewManager(ManagerConfig{ControlURL: server.URL, HostID: "host_01", Auth: &testAuth{}, Transport: server.Client().Transport, Credentials: store, Activator: initial, ControlToken: "local-token"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Enroll(context.Background(), "tunnel_resume_01", "local-resume-01"); err != nil {
		t.Fatal(err)
	}
	rejoined := &testActivator{}
	restarted, err := NewManager(ManagerConfig{ControlURL: server.URL, HostID: "host_01", Auth: &testAuth{}, Transport: server.Client().Transport, Credentials: store, Activator: rejoined, ControlToken: "local-token"})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	if serverCalls != 2 || rejoined.calls != 1 {
		t.Fatalf("resume server calls=%d activations=%d", serverCalls, rejoined.calls)
	}
	want := initial.input
	got := rejoined.input
	if got.AccountID != want.AccountID || got.TunnelID != want.TunnelID || got.HostID != want.HostID || got.ConnectorID != want.ConnectorID || got.OperationID != want.OperationID || got.CredentialReference != want.CredentialReference || got.CredentialKeyID != want.CredentialKeyID || got.CredentialThumbprint != want.CredentialThumbprint || got.CredentialGeneration != want.CredentialGeneration || got.ProcessGeneration != want.ProcessGeneration || !bytes.Equal(got.CredentialPublicKey, want.CredentialPublicKey) {
		t.Fatalf("resume binding\n got=%+v\nwant=%+v", got, want)
	}
}

func TestFileCredentialStoreRotationKeyIsReferenceOnlyAndDeletable(t *testing.T) {
	store, err := NewFileCredentialStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := store.Put(context.Background(), private)
	clear(private)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reference.PublicKey, public) || reference.Reference == "" || bytes.Contains([]byte(reference.Reference), public) {
		t.Fatalf("unsafe key projection=%+v", reference)
	}
	payload := []byte("paperboat connector rotation proof")
	signature, err := store.Sign(context.Background(), reference.Reference, payload)
	if err != nil || !ed25519.Verify(public, payload, signature) {
		t.Fatalf("reference signer err=%v", err)
	}
	journal, err := store.loadJournal()
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(journal)
	if bytes.Contains(encoded, signature) || bytes.Contains(encoded, public) || bytes.Contains(encoded, []byte("private")) {
		t.Fatalf("journal disclosed credential bytes: %s", encoded)
	}
	if err := store.Delete(context.Background(), reference.Reference); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Sign(context.Background(), reference.Reference, payload); !errors.Is(err, ErrSecretStore) {
		t.Fatalf("deleted key remained usable: %v", err)
	}
	if err := store.Delete(context.Background(), reference.Reference); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}

func TestCredentialPromotionIsAtomicAndIdempotentAcrossCrashRetry(t *testing.T) {
	store, err := NewFileCredentialStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	oldCredential, err := store.CreateKey(context.Background(), "credential-promotion-old")
	if err != nil {
		t.Fatal(err)
	}
	readyAt := time.Now().UTC()
	previous := ActivationRequest{AccountID: "account_01", TunnelID: "tunnel_promotion_01", HostID: "host_01", ConnectorID: "connector_promotion_01", OperationID: "operation_enroll_01", StableEndpointID: "123e4567-e89b-12d3-a456-426614174000", CredentialReference: oldCredential.Reference, CredentialKeyID: oldCredential.KeyID, CredentialThumbprint: oldCredential.Thumbprint, CredentialPublicKey: oldCredential.PublicKey, CredentialGeneration: 3, ProcessGeneration: 7}
	projection := Projection{Schema: Schema, Kind: "tunnel_connector", TunnelID: previous.TunnelID, HostID: previous.HostID, ConnectorID: previous.ConnectorID, OperationID: previous.OperationID, State: "ready", CredentialReference: previous.CredentialReference, CredentialGeneration: previous.CredentialGeneration, ReadyAt: &readyAt}
	state := journal{Version: 1, Records: map[string]record{previous.TunnelID: {AccountID: previous.AccountID, TunnelID: previous.TunnelID, HostID: previous.HostID, LocalKey: "local-promotion-01", IssueKey: "issue-promotion-01", ExchangeKey: "exchange-promotion-01", Credential: oldCredential, EnrollmentID: "enrollment_promotion_01", TokenReference: "token-enrollment_promotion_01", ConnectorID: previous.ConnectorID, OperationID: previous.OperationID, StableEndpointID: previous.StableEndpointID, CredentialGeneration: previous.CredentialGeneration, ProcessGeneration: previous.ProcessGeneration, Phase: "active", Projection: &projection}}}
	if err := store.saveJournal(state); err != nil {
		t.Fatal(err)
	}
	newCredential, err := store.CreateKey(context.Background(), "credential-promotion-new")
	if err != nil {
		t.Fatal(err)
	}
	next := previous
	next.OperationID = "operation_rotation_01"
	next.CredentialReference, next.CredentialKeyID, next.CredentialThumbprint, next.CredentialPublicKey = newCredential.Reference, newCredential.KeyID, newCredential.Thumbprint, newCredential.PublicKey
	next.CredentialGeneration++
	next.ProcessGeneration++
	store.failSave = 1
	if err := store.promoteCredential(previous.TunnelID, previous, next); !errors.Is(err, ErrSecretStore) {
		t.Fatalf("failed promotion=%v", err)
	}
	unchanged, err := store.loadJournal()
	if err != nil {
		t.Fatal(err)
	}
	if got := unchanged.Records[previous.TunnelID]; got.Credential.Reference != previous.CredentialReference || got.CredentialGeneration != previous.CredentialGeneration || got.ProcessGeneration != previous.ProcessGeneration {
		t.Fatalf("failed promotion mutated durable record=%+v", got)
	}
	if err := store.promoteCredential(previous.TunnelID, previous, next); err != nil {
		t.Fatal(err)
	}
	if err := store.promoteCredential(previous.TunnelID, previous, next); err != nil {
		t.Fatalf("post-crash replay was not idempotent: %v", err)
	}
	promoted, err := store.loadJournal()
	if err != nil {
		t.Fatal(err)
	}
	if got := promoted.Records[previous.TunnelID]; got.Credential.Reference != next.CredentialReference || got.CredentialGeneration != next.CredentialGeneration || got.ProcessGeneration != next.ProcessGeneration || got.Projection.CredentialReference != next.CredentialReference {
		t.Fatalf("promoted record=%+v", got)
	}
}

func TestManagerResumesActivationWithoutReplayingSingleUseExchange(t *testing.T) {
	now := time.Now().UTC()
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/exchange") {
			w.WriteHeader(http.StatusAccepted)
			writeEnvelope(t, w, testServerActivation(now, "tunnel_02", "connector_02", "operation_02"))
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeEnvelope(t, w, serverEnrollment{Schema: "paperboat.preview-tunnel/v1", Kind: "connector_enrollment", ID: "enrollment_02", TunnelID: "tunnel_02", HostID: "host_01", Token: "pbce_" + strings.Repeat("q", 48), ExpiresAt: now.Add(time.Minute)})
	}))
	defer server.Close()
	store, _ := NewFileCredentialStore(t.TempDir())
	failed := &testActivator{err: errors.New("bootstrap unavailable")}
	manager, _ := NewManager(ManagerConfig{ControlURL: server.URL, HostID: "host_01", Auth: &testAuth{}, Transport: server.Client().Transport, Credentials: store, Activator: failed, ControlToken: "local-token"})
	if _, err := manager.Enroll(context.Background(), "tunnel_02", "local-request-02"); !errors.Is(err, ErrActivation) {
		t.Fatalf("err=%v", err)
	}
	success := &testActivator{}
	manager, _ = NewManager(ManagerConfig{ControlURL: server.URL, HostID: "host_01", Auth: &testAuth{}, Transport: server.Client().Transport, Credentials: store, Activator: success, ControlToken: "local-token"})
	if _, err := manager.Enroll(context.Background(), "tunnel_02", "local-request-03"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || success.calls != 1 {
		t.Fatalf("server calls=%d activations=%d", calls, success.calls)
	}
}

func TestManagerPersistenceFailurePreventsServerMutation(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer server.Close()
	store, _ := NewFileCredentialStore(t.TempDir())
	store.failSave = 1
	manager, _ := NewManager(ManagerConfig{ControlURL: server.URL, HostID: "host_01", Auth: &testAuth{}, Transport: server.Client().Transport, Credentials: store, Activator: &testActivator{}, ControlToken: "local-token"})
	if _, err := manager.Enroll(context.Background(), "tunnel_03", "local-request-04"); !errors.Is(err, ErrSecretStore) {
		t.Fatalf("err=%v", err)
	}
	if calls != 0 {
		t.Fatalf("server calls=%d", calls)
	}
}

func TestJournalRejectsImpossiblePhaseBeforeCredentialUse(t *testing.T) {
	store, err := NewFileCredentialStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.CreateKey(context.Background(), "credential-corrupt-01")
	if err != nil {
		t.Fatal(err)
	}
	state := journal{Version: 1, Records: map[string]record{
		"tunnel_corrupt_01": {TunnelID: "tunnel_corrupt_01", HostID: "host_01", LocalKey: "local-corrupt-01", IssueKey: "issue-corrupt-01", ExchangeKey: "exchange-corrupt-01", Credential: credential, Phase: "prepared"},
	}}
	if err := store.saveJournal(state); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.root, "journal.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"phase":"prepared"`), []byte(`"phase":"active"`), 1)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.loadJournal(); !errors.Is(err, ErrConflict) {
		t.Fatalf("corrupt journal error = %v", err)
	}
}

func TestLocalHandlerAuthenticationCancellationAndSafeProjection(t *testing.T) {
	now := time.Now().UTC()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/exchange") {
			w.WriteHeader(http.StatusAccepted)
			writeEnvelope(t, w, testServerActivation(now, "tunnel_04", "connector_04", "operation_04"))
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeEnvelope(t, w, serverEnrollment{Schema: "paperboat.preview-tunnel/v1", Kind: "connector_enrollment", ID: "enrollment_04", TunnelID: "tunnel_04", HostID: "host_01", Token: "pbce_" + strings.Repeat("z", 48), ExpiresAt: now.Add(time.Minute)})
	}))
	defer server.Close()
	store, _ := NewFileCredentialStore(t.TempDir())
	manager, _ := NewManager(ManagerConfig{ControlURL: server.URL, HostID: "host_01", Auth: &testAuth{}, Transport: server.Client().Transport, Credentials: store, Activator: &testActivator{}, ControlToken: "local-token"})
	local := httptest.NewServer(manager)
	defer local.Close()
	unauthorized, _ := http.Post(local.URL+"/v1/tunnel-connectors/enroll", "application/json", strings.NewReader(`{}`))
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", unauthorized.StatusCode)
	}
	unauthorized.Body.Close()
	client, err := NewLocalClient(local.URL, "local-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := client.Enroll(context.Background(), "tunnel_04", "local-request-05")
	if err != nil || projection.ConnectorID != "connector_04" {
		t.Fatalf("projection=%+v err=%v", projection, err)
	}
	encoded, _ := json.Marshal(projection)
	if bytes.Contains(encoded, []byte("pbce_")) || bytes.Contains(encoded, []byte("private")) {
		t.Fatalf("unsafe response %s", encoded)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = client.Enroll(ctx, "tunnel_05", "local-request-06"); err == nil {
		t.Fatal("canceled request succeeded")
	}
}

func TestConnectorCredentialProofTranscriptMatchesContract(t *testing.T) {
	token := "pbce_" + strings.Repeat("a", 48)
	raw := connectorCredentialProofPayload("tunnel_1", "host_1", token, "protected-file://paperboat/connectors/key_1", "thumbprint_1", "idempotency_1")
	if bytes.Contains(raw, []byte(token)) {
		t.Fatal("transcript leaked token")
	}
	digest := sha256.Sum256([]byte(token))
	if !bytes.Contains(raw, []byte(`"enrollment_token_sha256":"`+fmt.Sprintf("%x", digest[:])+`"`)) {
		t.Fatalf("payload=%s", raw)
	}
}

func TestManagerMapsStaleRevokedAndUnavailableMachineIdentity(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   error
	}{
		{name: "stale identity", status: http.StatusUnauthorized, want: ErrAuthentication},
		{name: "revoked identity", status: http.StatusForbidden, want: ErrForbidden},
		{name: "control unavailable", status: http.StatusServiceUnavailable, want: ErrUnavailable},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(`{"error":{"code":"safe"}}`))
			}))
			defer server.Close()
			store, err := NewFileCredentialStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			manager, err := NewManager(ManagerConfig{ControlURL: server.URL, HostID: "host_01", Auth: &testAuth{}, Transport: server.Client().Transport, Credentials: store, Activator: &testActivator{}, ControlToken: "local-token"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Enroll(context.Background(), fmt.Sprintf("tunnel_identity_%d", index), fmt.Sprintf("local-identity-%d", index)); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func writeEnvelope(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(map[string]any{"data": value}); err != nil {
		t.Fatal(err)
	}
}

func testServerActivation(now time.Time, tunnelID, connectorID, operationID string) map[string]any {
	return map[string]any{
		"schema": "paperboat.preview-tunnel/v1", "kind": "connector_activation", "account_id": "account_01", "tunnel_id": tunnelID, "connector_id": connectorID, "host_id": "host_01",
		"stable_endpoint_id":    "123e4567-e89b-12d3-a456-426614174000",
		"credential_generation": 3, "process_generation": 2,
		"operation": map[string]any{"schema": "paperboat.preview-tunnel/v1", "kind": "operation", "id": operationID, "resource_kind": "connector", "resource_id": connectorID, "phase": "connecting", "state": "running", "progress": 60, "retrying": false, "correlation_id": "correlation_01", "created_at": now, "updated_at": now},
	}
}
