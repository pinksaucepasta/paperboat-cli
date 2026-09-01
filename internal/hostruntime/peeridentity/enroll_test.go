package peeridentity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	identitystore "github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

type staticCredentials struct{}

func (staticCredentials) Token(context.Context) (string, error) { return strings.Repeat("t", 32), nil }
func (staticCredentials) Proof(context.Context, string, string, string, []byte) ([]byte, error) {
	return []byte("proof"), nil
}

func TestEnsureResumesPendingEnrollmentAndPersistsApprovedCertificate(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "identity")
	store, err := identitystore.Open(identitystore.Config{StateRoot: stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	key := store.Current()
	if err := store.SaveRegistration(identitystore.Registration{ServerURL: "https://api.example.test", MachineID: "machine_01", EnvironmentID: "env_01", PublicKeyID: key.ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(key.Public()), InboxPath: filepath.Join(stateRoot, "inbox"), InstallationGeneration: 3, SetupRoles: []string{"host"}, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(nil)
	extraPublic, _, _ := ed25519.GenerateKey(nil)
	extraFingerprint := sha256.Sum256(extraPublic)
	var approved atomic.Bool
	var requested atomic.Bool
	var request struct {
		OperationID    string `json:"operation_id"`
		Generation     uint64 `json:"generation"`
		NoisePublicKey string `json:"noise_public_key"`
		QUICPublicKey  string `json:"quic_public_key"`
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/machine-peer-identity":
			if requested.Swap(true) {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":{"code":"operation_conflict"}}`))
				return
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			noise, _ := base64.RawURLEncoding.DecodeString(request.NoisePublicKey)
			quic, _ := base64.RawURLEncoding.DecodeString(request.QUICPublicKey)
			var noiseKey [32]byte
			copy(noiseKey[:], noise)
			response := map[string]any{"request_id": "per_abcdefghijklmnop", "endpoint_id": "machine_01", "generation": 3, "noise_public_key": request.NoisePublicKey, "quic_public_key": request.QUICPublicKey, "expires_at": now.Add(5 * time.Minute), "safety_code": safetyCode("machine_01", 3, noiseKey, quic)}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": response})
		case "/v1/machine-peer-identity/status":
			if !approved.Load() {
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(`{"data":{"state":"pending"}}`))
				return
			}
			noise, _ := base64.RawURLEncoding.DecodeString(request.NoisePublicKey)
			quic, _ := base64.RawURLEncoding.DecodeString(request.QUICPublicKey)
			var noiseKey [32]byte
			copy(noiseKey[:], noise)
			certificate, err := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{AccountID: "account_01", Role: endpointidentity.RoleMachine, EndpointID: "machine_01", NoisePublicKey: noiseKey, QUICPublicKey: quic, Generation: 3, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := certificate.MarshalBinary()
			rootFingerprint := sha256.Sum256(rootPublic)
			certificateFingerprint := sha256.Sum256(raw)
			certificateDocument := api.EndpointCertificateDocument{Version: 1, AccountID: "account_01", KeyID: "aek_" + hex.EncodeToString(rootFingerprint[:]), EndpointID: "machine_01", Role: "machine", Generation: 3, Serial: 1, IssuedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Certificate: base64.RawURLEncoding.EncodeToString(raw), CertificateFingerprint: hex.EncodeToString(certificateFingerprint[:])}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"state": "approved", "trusted_keys": []api.E2EEKey{
				{KeyID: certificateDocument.KeyID, PublicKey: base64.RawURLEncoding.EncodeToString(rootPublic), Fingerprint: hex.EncodeToString(rootFingerprint[:]), Generation: 1},
				{KeyID: "aek_" + hex.EncodeToString(extraFingerprint[:]), PublicKey: base64.RawURLEncoding.EncodeToString(extraPublic), Fingerprint: hex.EncodeToString(extraFingerprint[:]), Generation: 2},
			}, "certificate": certificateDocument}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := New(Config{ControlURL: server.URL, StateRoot: stateRoot, Transport: server.Client().Transport, Clock: func() time.Time { return now }}, staticCredentials{})
	if err != nil {
		t.Fatal(err)
	}
	var pending *PendingError
	if err := client.Ensure(context.Background()); !errors.As(err, &pending) || pending.SafetyCode == "" || pending.RequestID == "" {
		t.Fatalf("pending=%+v err=%v", pending, err)
	}
	if err := client.Ensure(context.Background()); !errors.Is(err, ErrPending) {
		t.Fatalf("repeated pending err=%v", err)
	}
	approved.Store(true)
	if err := client.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	endpoint, err := store.PeerEndpoint()
	if err != nil || len(endpoint.Certificate) == 0 {
		t.Fatalf("endpoint=%+v err=%v", endpoint, err)
	}
	if len(endpoint.TrustedKeys) != 2 {
		t.Fatalf("trusted endpoint roots=%d, want complete enrolled set", len(endpoint.TrustedKeys))
	}
	legacyPath := filepath.Join(stateRoot, "peer-endpoint.json")
	legacyRaw, err := os.ReadFile(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(legacyRaw, &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy, "trusted_keys")
	legacyRaw, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, legacyRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	legacyEndpoint, err := store.PeerEndpoint()
	if err != nil || len(legacyEndpoint.TrustedKeys) != 0 {
		t.Fatalf("legacy endpoint roots=%d err=%v, want refresh marker", len(legacyEndpoint.TrustedKeys), err)
	}
	if err := client.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	refreshed, err := store.PeerEndpoint()
	if err != nil || len(refreshed.TrustedKeys) != 2 {
		t.Fatalf("refreshed endpoint roots=%d err=%v", len(refreshed.TrustedKeys), err)
	}
}
