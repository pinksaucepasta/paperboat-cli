package localdaemon

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
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
