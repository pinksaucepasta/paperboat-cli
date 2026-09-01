package environmentenrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/environmentkey"
	identitystore "github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

type credentials struct{}

func (credentials) Token(context.Context) (string, error) { return strings.Repeat("t", 32), nil }
func (credentials) Proof(context.Context, string, string, string, []byte) ([]byte, error) {
	return []byte("machine-proof"), nil
}

type keySource struct{ material environmentkey.Material }

func (s keySource) Load(context.Context) (environmentkey.Material, error) { return s.material, nil }

type bindingReconciler struct{ state BindingState }

func (r *bindingReconciler) Reconcile(context.Context) (BindingState, error) { return r.state, nil }

func TestHostEnrollmentReconcilesApprovalAfterStartupAndExpiryWithoutDuplicateRequest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	stateRoot := filepath.Join(t.TempDir(), "runtime")
	identity, err := identitystore.Open(identitystore.Config{StateRoot: stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	key := identity.Current()
	if err := identity.SaveRegistration(identitystore.Registration{ServerURL: "https://api.example.test", MachineID: "machine_01", EnvironmentID: "account_01", PublicKeyID: key.ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(key.Public()), InboxPath: filepath.Join(stateRoot, "inbox"), InstallationGeneration: 3, SetupMode: "host", SetupRoles: []string{"host"}, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	peer, err := identity.PeerEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(nil)
	certificate, err := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{AccountID: "account_01", Role: endpointidentity.RoleMachine, EndpointID: "machine_01", NoisePublicKey: peer.NoisePublicKey(), QUICPublicKey: peer.QUICPublicKey(), Generation: 3, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	certificateBytes, _ := certificate.MarshalBinary()
	if err := identity.SavePeerEndpointCertificate(rootPublic, certificateBytes, now); err != nil {
		t.Fatal(err)
	}
	private, public, err := environmente2ee.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	var privateArray [32]byte
	copy(privateArray[:], private)
	material := environmentkey.Material{Generation: 3, Private: privateArray}
	kid, _ := environmente2ee.KeyIDX25519(public)
	var requestBody []byte
	postCount := 0
	replayPending := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/environment-key-enrollments":
			postCount++
			requestBody, _ = io.ReadAll(r.Body)
			var input struct {
				OperationID      string    `json:"operation_id"`
				RequestExpiresAt time.Time `json:"request_expires_at"`
			}
			if err := json.Unmarshal(requestBody, &input); err != nil {
				t.Fatal(err)
			}
			if r.Header.Get("Idempotency-Key") != input.OperationID {
				t.Fatalf("idempotency key=%q operation=%q", r.Header.Get("Idempotency-Key"), input.OperationID)
			}
			opBytes, _ := hex.DecodeString(strings.TrimPrefix(input.OperationID, "envop_"))
			var operation [16]byte
			copy(operation[:], opBytes)
			req := environmente2ee.EnrollmentRequest{AccountID: "account_01", OperationID: operation, SubjectKind: environmente2ee.SubjectHost, SubjectID: "machine_01", SubjectGeneration: 3, KeyGeneration: 3, EndpointCertificate: certificateBytes, RecipientPublic: public, RecipientKeyID: kid, RequestExpiresAt: uint64(input.RequestExpiresAt.Unix())}
			canonical, _ := environmente2ee.CanonicalEnrollmentRequest(req)
			digest := sha256.Sum256(canonical)
			challengeContext := environmente2ee.EnrollmentChallengeContext{AccountID: "account_01", RequestID: "enr_abcdefghijklmnop", OperationID: operation, RecipientKeyID: kid, RequestDigest: digest}
			sealed, _, err := environmente2ee.SealEnrollmentChallenge(challengeContext, public, nil)
			if err != nil {
				t.Fatal(err)
			}
			safety, _ := environmente2ee.EnrollmentSafetyCode(req)
			if replayPending {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"schema": "paperboat.environment-key-enrollment-state/v1", "request_id": "enr_abcdefghijklmnop", "state": "pending", "expires_at": input.RequestExpiresAt, "safety_code": safety, "enrollment_request": base64.RawURLEncoding.EncodeToString(canonical), "signing_proof": nil}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"schema": "paperboat.environment-key-enrollment-state/v1", "request_id": "enr_abcdefghijklmnop", "state": "challenge", "expires_at": input.RequestExpiresAt, "safety_code": safety, "enrollment_request": base64.RawURLEncoding.EncodeToString(canonical), "signing_proof": nil, "challenge": base64.RawURLEncoding.EncodeToString(sealed)}})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/environment-key-enrollments/enr_abcdefghijklmnop/proof":
			var input map[string]any
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input["proof"] == "" {
				t.Fatalf("proof=%v err=%v", input, err)
			}
			var initial struct {
				RequestExpiresAt time.Time `json:"request_expires_at"`
			}
			_ = json.Unmarshal(requestBody, &initial)
			var first struct {
				OperationID string `json:"operation_id"`
			}
			_ = json.Unmarshal(requestBody, &first)
			if r.Header.Get("Idempotency-Key") != first.OperationID {
				t.Fatalf("proof idempotency key=%q operation=%q", r.Header.Get("Idempotency-Key"), first.OperationID)
			}
			opBytes, _ := hex.DecodeString(strings.TrimPrefix(first.OperationID, "envop_"))
			var operation [16]byte
			copy(operation[:], opBytes)
			req := environmente2ee.EnrollmentRequest{AccountID: "account_01", OperationID: operation, SubjectKind: environmente2ee.SubjectHost, SubjectID: "machine_01", SubjectGeneration: 3, KeyGeneration: 3, EndpointCertificate: certificateBytes, RecipientPublic: public, RecipientKeyID: kid, RequestExpiresAt: uint64(initial.RequestExpiresAt.Unix())}
			canonical, _ := environmente2ee.CanonicalEnrollmentRequest(req)
			safety, _ := environmente2ee.EnrollmentSafetyCode(req)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"schema": "paperboat.environment-key-enrollment-state/v1", "request_id": "enr_abcdefghijklmnop", "state": "pending", "expires_at": initial.RequestExpiresAt, "safety_code": safety, "enrollment_request": base64.RawURLEncoding.EncodeToString(canonical), "signing_proof": nil}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	reconciler := &bindingReconciler{state: BindingUnknown}
	client, err := New(Config{ControlURL: server.URL, StateRoot: stateRoot, Transport: server.Client().Transport, Clock: func() time.Time { return now }, Keys: keySource{material}, Reconcile: reconciler.Reconcile}, credentials{})
	if err != nil {
		t.Fatal(err)
	}
	var pending *PendingError
	if err := client.Ensure(context.Background()); !errors.As(err, &pending) || pending.SafetyCode == "" {
		t.Fatalf("pending=%+v err=%v request=%s", pending, err, requestBody)
	}
	if err := client.Ensure(context.Background()); !errors.Is(err, ErrPending) {
		t.Fatalf("unapproved proof was reported as success: %v", err)
	}
	if postCount != 1 {
		t.Fatalf("initial enrollment POST count=%d, want 1", postCount)
	}
	clock := now
	client.config.Clock = func() time.Time { return clock }
	clock = now.Add(10 * time.Minute)
	if err := client.Ensure(context.Background()); !errors.Is(err, ErrPending) {
		t.Fatalf("expired proof without runtime reconciliation err=%v", err)
	}
	if postCount != 1 {
		t.Fatalf("expired proof created duplicate enrollment: POST count=%d", postCount)
	}
	reconciler.state = BindingActive
	if err := client.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if postCount != 1 {
		t.Fatalf("approved binding created duplicate enrollment: POST count=%d", postCount)
	}
	state, err := os.ReadFile(filepath.Join(stateRoot, "environment", "enrollment.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), base64.RawURLEncoding.EncodeToString(private)) {
		t.Fatal("private key persisted in enrollment state")
	}
	if bytes.Contains(requestBody, private) {
		t.Fatal("private key sent in enrollment request")
	}
	persisted, err := client.loadState()
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.Approved || !persisted.Proofed || persisted.Proof != "" {
		t.Fatalf("approved state not committed: %+v", persisted)
	}
	if err := os.Remove(filepath.Join(stateRoot, "environment", "enrollment.json")); err != nil {
		t.Fatal(err)
	}
	if err := client.Ensure(context.Background()); err != nil {
		t.Fatalf("pre-approved active binding with no journal: %v", err)
	}
	if postCount != 1 {
		t.Fatalf("pre-approved active binding created enrollment: POST count=%d", postCount)
	}
	reconciler.state = BindingUnknown
	replayPending = true
	clock = now
	if err := client.Ensure(context.Background()); !errors.Is(err, ErrPending) {
		t.Fatalf("idempotent POST replay err=%v", err)
	}
	if postCount != 2 {
		t.Fatalf("idempotent POST replay count=%d, want 2", postCount)
	}
	replacementPrivate, _, err := environmente2ee.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(replacementPrivate)
	var replacementArray [32]byte
	copy(replacementArray[:], replacementPrivate)
	client.config.Keys = keySource{environmentkey.Material{Generation: 4, Private: replacementArray}}
	if current, err := client.stateMatchesCurrentIdentity(context.Background(), persisted); err != nil || current {
		t.Fatalf("old proof state was reused for a replacement key: current=%v error=%v", current, err)
	}
}
