package localdaemon

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

func TestApproveOwnedPeerEnrollmentsAutomaticCLIApproval(t *testing.T) {
	for _, tc := range []struct {
		name         string
		mutate       func(*api.E2EERoot, *api.PendingEndpointIdentity)
		mutateResult func(*api.EndpointCertificateDocument)
		wantErr      bool
		wantAttempts int32
	}{
		{name: "success", wantAttempts: 1},
		{name: "expired", mutate: func(_ *api.E2EERoot, p *api.PendingEndpointIdentity) {
			p.ExpiresAt = time.Now().UTC().Add(-time.Minute)
		}, wantErr: true},
		{name: "denied role", mutate: func(_ *api.E2EERoot, p *api.PendingEndpointIdentity) { p.Role = "unknown" }, wantErr: true},
		{name: "denied state", mutate: func(_ *api.E2EERoot, p *api.PendingEndpointIdentity) { p.State = "fulfilled" }, wantErr: true},
		{name: "wrong account", mutate: func(r *api.E2EERoot, _ *api.PendingEndpointIdentity) {
			public, _, _ := ed25519.GenerateKey(nil)
			sum := sha256.Sum256(public)
			keyID := "aek_" + hex.EncodeToString(sum[:])
			r.TrustedKeys[0] = api.E2EEKey{KeyID: keyID, PublicKey: base64.RawURLEncoding.EncodeToString(public), Fingerprint: hex.EncodeToString(sum[:]), Generation: 1}
		}, wantErr: true},
		{name: "retry", mutate: func(_ *api.E2EERoot, _ *api.PendingEndpointIdentity) {}, wantErr: true, wantAttempts: 2},
		{name: "response fingerprint mismatch", mutateResult: func(document *api.EndpointCertificateDocument) {
			document.CertificateFingerprint = strings.Repeat("f", 64)
		}, wantErr: true, wantAttempts: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootDir := t.TempDir()
			store := config.ProfileStore{Path: rootDir, Secrets: config.FileSecretStore{Dir: filepath.Join(rootDir, "secrets")}}
			const accountID, daemonID, endpointID = "account_1", "cli_daemon", "cli_new"
			serverNow := time.Now().UTC().Truncate(time.Second)
			server := httptest.NewServer(nil)
			defer server.Close()
			keys, err := store.PeerIdentityKeys(server.URL, accountID, daemonID)
			if err != nil {
				t.Fatal(err)
			}
			defer clearPeerKeysForTest(&keys)
			pendingKeys, err := store.PeerEndpointKeys(server.URL, accountID, endpointID)
			if err != nil {
				t.Fatal(err)
			}
			quic := pendingKeys.QUICPrivate.Public().(ed25519.PublicKey)
			pending := api.PendingEndpointIdentity{RequestID: "per_0123456789abcdef", EndpointID: endpointID, Role: "cli", State: "pending", Generation: 1, NoisePublicKey: base64.RawURLEncoding.EncodeToString(pendingKeys.NoisePublic[:]), QUICPublicKey: base64.RawURLEncoding.EncodeToString(quic), CreatedAt: serverNow.Add(-time.Minute), ExpiresAt: serverNow.Add(4 * time.Minute), SafetyCode: "abcde-fghij"}
			rootPublic := keys.RootPrivate.Public().(ed25519.PublicKey)
			rootSum := sha256.Sum256(rootPublic)
			rootKeyID := "aek_" + hex.EncodeToString(rootSum[:])
			root := api.E2EERoot{Version: 1, TrustedKeys: []api.E2EEKey{{KeyID: rootKeyID, PublicKey: base64.RawURLEncoding.EncodeToString(rootPublic), Fingerprint: hex.EncodeToString(rootSum[:]), Generation: 1}}}
			if tc.mutate != nil {
				tc.mutate(&root, &pending)
			}
			var attempts int32
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				var value any
				switch r.URL.Path {
				case "/v1/e2ee/root":
					value = root
				case "/v1/e2ee/pending-endpoints":
					value = []api.PendingEndpointIdentity{pending}
				default:
					if r.Method != http.MethodPut {
						http.NotFound(w, r)
						return
					}
					attempt := atomic.AddInt32(&attempts, 1)
					if tc.name == "retry" && attempt == 1 {
						w.WriteHeader(http.StatusServiceUnavailable)
						_, _ = w.Write([]byte(`{"error":{"code":"retry","message":"retry"}}`))
						return
					}
					var document api.EndpointCertificateDocument
					if err := json.NewDecoder(r.Body).Decode(&document); err != nil {
						t.Fatal(err)
					}
					if tc.mutateResult != nil {
						tc.mutateResult(&document)
					}
					value = document
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": value})
			})
			client := api.New(server.URL, config.Credential{AccessToken: "token"}, server.Client())
			profile := config.Profile{Issuer: server.URL, Account: config.Account{ID: accountID}, CLIClientSessionID: daemonID}
			err = ApproveOwnedPeerEnrollments(t.Context(), store, profile, client, nil)
			if tc.wantErr != (err != nil) {
				t.Fatalf("err=%v", err)
			}
			if tc.name == "retry" && err != nil {
				err = ApproveOwnedPeerEnrollments(t.Context(), store, profile, client, nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			if got := atomic.LoadInt32(&attempts); got != tc.wantAttempts {
				t.Fatalf("PUT attempts=%d want=%d", got, tc.wantAttempts)
			}
		})
	}
}

func TestApproveOwnedPeerEnrollmentsVerifierOnlyReturnsTypedNonSignerForMixedPending(t *testing.T) {
	rootDir := t.TempDir()
	store := config.ProfileStore{Path: rootDir, Secrets: config.FileSecretStore{Dir: filepath.Join(rootDir, "secrets")}}
	const accountID, daemonID = "account_1", "cli_daemon"
	serverNow := time.Now().UTC().Truncate(time.Second)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rootSum := sha256.Sum256(rootPublic)
	if err := store.SavePeerAccountRootPublic("https://api.example.test", accountID, rootPublic); err != nil {
		t.Fatal(err)
	}
	endpointKeys, err := store.PeerEndpointKeys("https://api.example.test", accountID, daemonID)
	if err != nil {
		t.Fatal(err)
	}
	quicPublic := endpointKeys.QUICPrivate.Public().(ed25519.PublicKey)
	verifierCertificate, err := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{AccountID: accountID, Role: endpointidentity.RoleCLI, EndpointID: daemonID, NoisePublicKey: endpointKeys.NoisePublic, QUICPublicKey: quicPublic, Generation: 1, Serial: 1, IssuedAt: serverNow.Add(-time.Minute), ExpiresAt: serverNow.Add(time.Hour)})
	clear(rootPrivate)
	clearPeerKeysForTest(&endpointKeys)
	if err != nil {
		t.Fatal(err)
	}
	verifierRaw, err := verifierCertificate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SavePeerCertificate("https://api.example.test", daemonID, verifierRaw); err != nil {
		t.Fatal(err)
	}
	clear(verifierRaw)
	pending := []api.PendingEndpointIdentity{
		{RequestID: "per_cli_0123456789", EndpointID: "cli_new", Role: "cli", State: "pending", Generation: 1, CreatedAt: serverNow, ExpiresAt: serverNow.Add(time.Minute), SafetyCode: "abcde-fghij"},
		{RequestID: "per_machine_012345", EndpointID: "machine_1", Role: "machine", State: "pending", Generation: 1, CreatedAt: serverNow, ExpiresAt: serverNow.Add(time.Minute), SafetyCode: "klmno-pqrst"},
	}
	var puts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPut {
			atomic.AddInt32(&puts, 1)
		}
		switch r.URL.Path {
		case "/v1/e2ee/pending-endpoints":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": pending})
		case "/v1/e2ee/root":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.E2EERoot{Version: 1, TrustedKeys: []api.E2EEKey{{KeyID: "aek_" + hex.EncodeToString(rootSum[:]), PublicKey: base64.RawURLEncoding.EncodeToString(rootPublic), Fingerprint: hex.EncodeToString(rootSum[:]), Generation: 1}}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	profile := config.Profile{Issuer: "https://api.example.test", Account: config.Account{ID: accountID}, CLIClientSessionID: daemonID}
	client := api.New(server.URL, config.Credential{AccessToken: "token"}, server.Client())
	err = ApproveOwnedPeerEnrollments(t.Context(), store, profile, client, []api.UserMachine{{ID: "machine_1", State: "active"}})
	var unavailable *PeerApprovalSignerUnavailableError
	if !errors.As(err, &unavailable) || unavailable.PendingRequests != 2 || !errors.Is(err, ErrPeerApprovalSignerUnavailable) || atomic.LoadInt32(&puts) != 0 {
		t.Fatalf("unavailable=%+v puts=%d err=%v root=%x", unavailable, puts, err, rootSum)
	}
}

func TestApproveOwnedPeerEnrollmentsVerifierOnlyRootFailuresRemainHard(t *testing.T) {
	for _, tc := range []struct {
		name            string
		saveLocalPublic bool
		mismatchRemote  bool
		rootStatus      int
	}{
		{name: "missing local verifier"},
		{name: "remote root mismatch", saveLocalPublic: true, mismatchRemote: true},
		{name: "root API failure", saveLocalPublic: true, rootStatus: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootDir := t.TempDir()
			store := config.ProfileStore{Path: rootDir, Secrets: config.FileSecretStore{Dir: filepath.Join(rootDir, "secrets")}}
			localPublic, _, _ := ed25519.GenerateKey(nil)
			if tc.saveLocalPublic {
				if err := store.SavePeerAccountRootPublic("https://api.example.test", "account_1", localPublic); err != nil {
					t.Fatal(err)
				}
			}
			remotePublic := localPublic
			if tc.mismatchRemote {
				remotePublic, _, _ = ed25519.GenerateKey(nil)
			}
			remoteFingerprint := sha256.Sum256(remotePublic)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v1/e2ee/pending-endpoints":
					_ = json.NewEncoder(w).Encode(map[string]any{"data": []api.PendingEndpointIdentity{{RequestID: "per_cli_0123456789", EndpointID: "cli_new", Role: "cli", State: "pending", Generation: 1, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute), SafetyCode: "abcde-fghij"}}})
				case "/v1/e2ee/root":
					if tc.rootStatus != 0 {
						w.WriteHeader(tc.rootStatus)
						_, _ = w.Write([]byte(`{"error":{"code":"temporarily_unavailable","message":"unavailable"}}`))
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": api.E2EERoot{Version: 1, TrustedKeys: []api.E2EEKey{{KeyID: "aek_" + hex.EncodeToString(remoteFingerprint[:]), PublicKey: base64.RawURLEncoding.EncodeToString(remotePublic), Fingerprint: hex.EncodeToString(remoteFingerprint[:]), Generation: 1}}}})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			profile := config.Profile{Issuer: "https://api.example.test", Account: config.Account{ID: "account_1"}, CLIClientSessionID: "cli_daemon"}
			err := ApproveOwnedPeerEnrollments(t.Context(), store, profile, api.New(server.URL, config.Credential{AccessToken: "token"}, server.Client()), nil)
			var unavailable *PeerApprovalSignerUnavailableError
			if err == nil || errors.As(err, &unavailable) || errors.Is(err, ErrPeerApprovalSignerUnavailable) {
				t.Fatalf("non-custody failure was suppressed: unavailable=%+v err=%v", unavailable, err)
			}
		})
	}
}

func TestApproveOwnedPeerEnrollmentsVerifierOnlyWithoutPendingNeedsNoSigner(t *testing.T) {
	rootDir := t.TempDir()
	store := config.ProfileStore{Path: rootDir, Secrets: config.FileSecretStore{Dir: filepath.Join(rootDir, "secrets")}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []api.PendingEndpointIdentity{}})
	}))
	defer server.Close()
	profile := config.Profile{Issuer: server.URL, Account: config.Account{ID: "account_1"}, CLIClientSessionID: "cli_daemon"}
	if err := ApproveOwnedPeerEnrollments(t.Context(), store, profile, api.New(server.URL, config.Credential{AccessToken: "token"}, server.Client()), nil); err != nil {
		t.Fatal(err)
	}
}

func clearPeerKeysForTest(keys *config.PeerIdentityKeys) {
	for i := range keys.RootPrivate {
		keys.RootPrivate[i] = 0
	}
	for i := range keys.QUICPrivate {
		keys.QUICPrivate[i] = 0
	}
	for i := range keys.NoisePrivate {
		keys.NoisePrivate[i] = 0
	}
}
