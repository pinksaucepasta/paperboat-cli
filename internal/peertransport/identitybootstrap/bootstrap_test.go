package identitybootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

type bootstrapClientFunc func(context.Context, string, api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error)

type freshBootstrapClientFunc func(context.Context, string, api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error)

func (f freshBootstrapClientFunc) E2EERoot(context.Context) (api.E2EERoot, error) {
	return api.E2EERoot{}, &api.APIError{Status: 404, Code: "not_found"}
}
func (f freshBootstrapClientFunc) BootstrapE2EE(ctx context.Context, operation string, input api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
	return f(ctx, operation, input)
}
func (f freshBootstrapClientFunc) BootstrapE2EEFresh(ctx context.Context, operation string, input api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
	return f(ctx, operation, input)
}
func (freshBootstrapClientFunc) RequestCLIEndpoint(context.Context, api.CLIEndpointRequestInput) (api.PendingEndpointIdentity, error) {
	return api.PendingEndpointIdentity{}, errors.New("fresh bootstrap must not request endpoint enrollment")
}
func (freshBootstrapClientFunc) EndpointCertificate(context.Context, string, uint64) (api.EndpointCertificateDocument, error) {
	return api.EndpointCertificateDocument{}, errors.New("fresh bootstrap must not poll endpoint enrollment")
}

func (bootstrapClientFunc) E2EERoot(context.Context) (api.E2EERoot, error) {
	return api.E2EERoot{}, &api.APIError{Status: 404, Code: "not_found"}
}
func (bootstrapClientFunc) RequestCLIEndpoint(context.Context, api.CLIEndpointRequestInput) (api.PendingEndpointIdentity, error) {
	return api.PendingEndpointIdentity{}, errors.New("existing-root enrollment must not run")
}
func (bootstrapClientFunc) EndpointCertificate(context.Context, string, uint64) (api.EndpointCertificateDocument, error) {
	return api.EndpointCertificateDocument{}, errors.New("existing-root enrollment must not run")
}

type existingRootClient struct{ root api.E2EERoot }

func (c existingRootClient) E2EERoot(context.Context) (api.E2EERoot, error) { return c.root, nil }
func (existingRootClient) BootstrapE2EE(context.Context, string, api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
	return api.E2EEBootstrapResult{}, errors.New("bootstrap must not run before pairing")
}

type newRootReplayClient struct {
	bootstrap bootstrapClientFunc
	root      api.E2EERoot
	rootCalls int
	requests  int
}

func (c *newRootReplayClient) E2EERoot(context.Context) (api.E2EERoot, error) {
	c.rootCalls++
	if len(c.root.TrustedKeys) == 0 {
		return api.E2EERoot{}, &api.APIError{Status: http.StatusNotFound, Code: "not_found"}
	}
	return c.root, nil
}

func (c *newRootReplayClient) BootstrapE2EE(ctx context.Context, operation string, input api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
	result, err := c.bootstrap(ctx, operation, input)
	if err == nil {
		public, decodeErr := base64.RawURLEncoding.Strict().DecodeString(input.RootPublicKey)
		if decodeErr != nil {
			return api.E2EEBootstrapResult{}, decodeErr
		}
		c.root = rootDocument(ed25519.PublicKey(public))
	}
	return result, err
}

func (c *newRootReplayClient) RequestCLIEndpoint(context.Context, api.CLIEndpointRequestInput) (api.PendingEndpointIdentity, error) {
	c.requests++
	return api.PendingEndpointIdentity{}, errors.New("completed first-root enrollment must not request another certificate")
}

func (*newRootReplayClient) EndpointCertificate(context.Context, string, uint64) (api.EndpointCertificateDocument, error) {
	return api.EndpointCertificateDocument{}, errors.New("completed first-root enrollment must not poll another certificate")
}

type existingEnrollmentClient struct {
	root        api.E2EERoot
	pending     api.PendingEndpointIdentity
	certificate api.EndpointCertificateDocument
	requests    int
	certReads   int
}

func (c *existingEnrollmentClient) E2EERoot(context.Context) (api.E2EERoot, error) {
	return c.root, nil
}
func (*existingEnrollmentClient) BootstrapE2EE(context.Context, string, api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
	return api.E2EEBootstrapResult{}, errors.New("first-root bootstrap must not run")
}
func (c *existingEnrollmentClient) RequestCLIEndpoint(_ context.Context, input api.CLIEndpointRequestInput) (api.PendingEndpointIdentity, error) {
	c.requests++
	if input.EndpointID != c.pending.EndpointID || input.Generation != c.pending.Generation || input.NoisePublicKey != c.pending.NoisePublicKey || input.QUICPublicKey != c.pending.QUICPublicKey {
		return api.PendingEndpointIdentity{}, errors.New("request key mismatch")
	}
	return c.pending, nil
}
func (c *existingEnrollmentClient) EndpointCertificate(context.Context, string, uint64) (api.EndpointCertificateDocument, error) {
	c.certReads++
	if c.certificate.Certificate == "" {
		return api.EndpointCertificateDocument{}, &api.APIError{Status: http.StatusNotFound, Code: "not_found"}
	}
	return c.certificate, nil
}

func TestEnrollCLIExistingRootStoresVerifierOnlyIdentityAndIsIdempotent(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(nil)
	root := rootDocument(rootPublic)
	rootDir := t.TempDir()
	store := config.ProfileStore{Path: rootDir, Secrets: config.FileSecretStore{Dir: filepath.Join(rootDir, "secrets")}}
	keys, err := store.PeerEndpointKeys("https://api.example.test", "account_1", "cli_1")
	if err != nil {
		t.Fatal(err)
	}
	quicPublic := keys.QUICPrivate.Public().(ed25519.PublicKey)
	certificate, err := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{AccountID: "account_1", Role: endpointidentity.RoleCLI, EndpointID: "cli_1", NoisePublicKey: keys.NoisePublic, QUICPublicKey: quicPublic, Generation: 1, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := certificate.MarshalBinary()
	certificateFingerprint := sha256.Sum256(raw)
	client := &existingEnrollmentClient{root: root, pending: api.PendingEndpointIdentity{RequestID: "per_0123456789abcdef", EndpointID: "cli_1", Role: "cli", State: "pending", Generation: 1, NoisePublicKey: base64.RawURLEncoding.EncodeToString(keys.NoisePublic[:]), QUICPublicKey: base64.RawURLEncoding.EncodeToString(quicPublic), CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(4 * time.Minute), SafetyCode: "abcde-fghij"}, certificate: api.EndpointCertificateDocument{Version: 1, AccountID: "account_1", KeyID: rootKeyID(rootPublic), EndpointID: "cli_1", Role: "cli", Generation: 1, Serial: 1, IssuedAt: certificate.Claims.IssuedAt.Format(time.RFC3339), ExpiresAt: certificate.Claims.ExpiresAt.Format(time.RFC3339), Certificate: base64.RawURLEncoding.EncodeToString(raw), CertificateFingerprint: hex.EncodeToString(certificateFingerprint[:])}}
	request := CLIRequest{Store: store, Client: client, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_1", Now: func() time.Time { return now }, PollInterval: time.Millisecond, Timeout: time.Second}
	first, err := EnrollCLI(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EnrollCLI(context.Background(), request)
	if err != nil || client.requests != 1 || second.RootFingerprint != first.RootFingerprint || second.CertificateFingerprint != first.CertificateFingerprint {
		t.Fatalf("second enrollment failed: requests=%d result=%+v err=%v", client.requests, second, err)
	}
	storedRoot, err := store.LoadPeerAccountRootPublic(request.Issuer, request.AccountID)
	if err != nil || !bytes.Equal(storedRoot, rootPublic) {
		t.Fatalf("stored root=%x err=%v", storedRoot, err)
	}
	clear(storedRoot)
	if _, err := store.ExportPeerAccountRootSeed(request.Issuer, request.AccountID); !errors.Is(err, config.ErrSecretNotFound) {
		t.Fatalf("existing root private seed was created: %v", err)
	}
	if _, err := store.LoadPeerCertificate(request.Issuer, request.CLIClientSessionID); err != nil {
		t.Fatal(err)
	}
}

func TestEnrollExistingRootRecoversAlreadyFulfilledEnrollmentAfterLocalPersistenceFailure(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(nil)
	rootDir := t.TempDir()
	store := config.ProfileStore{Path: rootDir, Secrets: config.FileSecretStore{Dir: filepath.Join(rootDir, "secrets")}}
	keys, err := store.PeerEndpointKeys("https://api.example.test", "account_1", "cli_1")
	if err != nil {
		t.Fatal(err)
	}
	quicPublic := keys.QUICPrivate.Public().(ed25519.PublicKey)
	certificate, err := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{AccountID: "account_1", Role: endpointidentity.RoleCLI, EndpointID: "cli_1", NoisePublicKey: keys.NoisePublic, QUICPublicKey: quicPublic, Generation: 1, Serial: 1, IssuedAt: now.Add(-10 * time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := certificate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	certificateFingerprint := sha256.Sum256(raw)
	client := &existingEnrollmentClient{
		root:        rootDocument(rootPublic),
		pending:     api.PendingEndpointIdentity{RequestID: "per_0123456789abcdef", EndpointID: "cli_1", Role: "cli", State: "fulfilled", Generation: 1, NoisePublicKey: base64.RawURLEncoding.EncodeToString(keys.NoisePublic[:]), QUICPublicKey: base64.RawURLEncoding.EncodeToString(quicPublic), CreatedAt: now.Add(-10 * time.Minute), ExpiresAt: now.Add(-5 * time.Minute), SafetyCode: "abcde-fghij"},
		certificate: api.EndpointCertificateDocument{Version: 1, AccountID: "account_1", KeyID: rootKeyID(rootPublic), EndpointID: "cli_1", Role: "cli", Generation: 1, Serial: 1, IssuedAt: certificate.Claims.IssuedAt.Format(time.RFC3339), ExpiresAt: certificate.Claims.ExpiresAt.Format(time.RFC3339), Certificate: base64.RawURLEncoding.EncodeToString(raw), CertificateFingerprint: hex.EncodeToString(certificateFingerprint[:])},
	}
	result, err := EnrollExistingRoot(context.Background(), ExistingRootRequest{Store: store, Client: client, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_1", Now: func() time.Time { return now }, PollInterval: time.Millisecond, Timeout: time.Second})
	if err != nil || result.CertificateFingerprint != hex.EncodeToString(certificateFingerprint[:]) || client.certReads != 1 {
		t.Fatalf("result=%+v certificate reads=%d err=%v", result, client.certReads, err)
	}
	if _, err := store.LoadPeerCertificate("https://api.example.test", "cli_1"); err != nil {
		t.Fatalf("issued certificate was not recovered: %v", err)
	}
}

func TestEnrollExistingRootExpiresWhileApprovalIsPending(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	rootPublic, _, _ := ed25519.GenerateKey(nil)
	rootDir := t.TempDir()
	store := config.ProfileStore{Path: rootDir, Secrets: config.FileSecretStore{Dir: filepath.Join(rootDir, "secrets")}}
	keys, err := store.PeerEndpointKeys("https://api.example.test", "account_1", "cli_1")
	if err != nil {
		t.Fatal(err)
	}
	quicPublic := keys.QUICPrivate.Public().(ed25519.PublicKey)
	client := &existingEnrollmentClient{root: rootDocument(rootPublic), pending: api.PendingEndpointIdentity{RequestID: "per_0123456789abcdef", EndpointID: "cli_1", Role: "cli", State: "pending", Generation: 1, NoisePublicKey: base64.RawURLEncoding.EncodeToString(keys.NoisePublic[:]), QUICPublicKey: base64.RawURLEncoding.EncodeToString(quicPublic), CreatedAt: now, ExpiresAt: now.Add(time.Minute), SafetyCode: "abcde-fghij"}}
	err = nil
	_, err = EnrollExistingRoot(context.Background(), ExistingRootRequest{Store: store, Client: client, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_1", Now: func() time.Time { return now }, PollInterval: time.Millisecond, Timeout: 10 * time.Millisecond})
	if !errors.Is(err, ErrEnrollmentExpired) {
		t.Fatalf("err=%v", err)
	}
}

func (f bootstrapClientFunc) BootstrapE2EE(ctx context.Context, operation string, input api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
	return f(ctx, operation, input)
}

func TestEnrollCLINewRootCreatesPersistsAndExactlyReplaysIdentity(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	store := config.ProfileStore{Path: root, Secrets: config.FileSecretStore{Dir: filepath.Join(root, "secrets")}}
	var firstOperation string
	var firstInput api.E2EEBootstrapInput
	client := &newRootReplayClient{bootstrap: bootstrapClientFunc(func(_ context.Context, operation string, input api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
		if firstOperation == "" {
			firstOperation, firstInput = operation, input
		} else if operation != firstOperation || input != firstInput {
			t.Fatalf("bootstrap replay changed: %q %+v", operation, input)
		}
		rootPublic, err := base64.RawURLEncoding.DecodeString(input.RootPublicKey)
		if err != nil || len(rootPublic) != ed25519.PublicKeySize {
			t.Fatal("invalid root public key")
		}
		raw, _ := base64.RawURLEncoding.DecodeString(input.Certificate.Certificate)
		certificate, err := endpointidentity.Verify(raw, ed25519.PublicKey(rootPublic), endpointidentity.Expected{AccountID: "account_1", Role: endpointidentity.RoleCLI, EndpointID: "cli_1", Generation: 1}, now)
		if err != nil || certificate.Claims.Serial != 1 {
			t.Fatalf("certificate=%+v err=%v", certificate, err)
		}
		return bootstrapResult(input), nil
	})}
	request := CLIRequest{Store: store, Client: client, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_1", Now: func() time.Time { return now }, PollInterval: time.Millisecond, Timeout: time.Second}
	first, err := EnrollCLI(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EnrollCLI(context.Background(), request)
	if err != nil || client.requests != 0 || second.RootFingerprint != first.RootFingerprint || second.CertificateFingerprint != first.CertificateFingerprint {
		t.Fatalf("second enrollment did not replay: requests=%d result=%+v err=%v", client.requests, second, err)
	}
}

func TestFreshBootstrapPersistsIdentityBeforeReturning(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	store := config.ProfileStore{Path: root, Secrets: config.FileSecretStore{Dir: filepath.Join(root, "secrets")}}
	client := freshBootstrapClientFunc(func(_ context.Context, _ string, input api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
		return bootstrapResult(input), nil
	})
	request := CLIRequest{Store: store, Client: client, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_fresh", Now: func() time.Time { return now }, Fresh: true}
	result, err := EnrollCLI(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	rootPublic, err := store.LoadPeerAccountRootPublic(request.Issuer, request.AccountID)
	if err != nil || len(rootPublic) != ed25519.PublicKeySize {
		t.Fatalf("stored root err=%v", err)
	}
	stored, err := store.LoadPeerCertificate(request.Issuer, request.CLIClientSessionID)
	if err != nil {
		t.Fatalf("stored certificate: %v", err)
	}
	if got := sha256.Sum256(stored.Raw); hex.EncodeToString(got[:]) != result.CertificateFingerprint {
		t.Fatalf("stored certificate fingerprint=%x want=%s", got, result.CertificateFingerprint)
	}
}

func TestFreshBootstrapUsesEndpointScopedSigningKeyAndExactlyReplays(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	store := config.ProfileStore{Path: root, Secrets: config.FileSecretStore{Dir: filepath.Join(root, "secrets")}}
	old, err := store.PeerIdentityKeys("https://api.example.test", "account_1", "cli_old")
	if err != nil {
		t.Fatal(err)
	}
	oldPublic := append(ed25519.PublicKey(nil), old.RootPrivate.Public().(ed25519.PublicKey)...)
	clearKeys(&old)

	var firstOperation, firstPublic string
	client := freshBootstrapClientFunc(func(_ context.Context, operation string, input api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
		if firstOperation == "" {
			firstOperation, firstPublic = operation, input.RootPublicKey
		} else if operation != firstOperation || input.RootPublicKey != firstPublic {
			t.Fatal("fresh enrollment retry changed its durable endpoint identity")
		}
		return bootstrapResult(input), nil
	})
	request := CLIRequest{Store: store, Client: client, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_fresh", Now: func() time.Time { return now }, Fresh: true}
	first, err := EnrollCLI(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EnrollCLI(context.Background(), request)
	if err != nil || second.RootFingerprint != first.RootFingerprint || second.CertificateFingerprint != first.CertificateFingerprint {
		t.Fatalf("fresh replay result=%+v want=%+v err=%v", second, first, err)
	}
	freshPublic, err := base64.RawURLEncoding.Strict().DecodeString(firstPublic)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(freshPublic)
	defer clear(oldPublic)
	if bytes.Equal(freshPublic, oldPublic) {
		t.Fatal("fresh enrollment reused the account-scoped signing identity")
	}
}

func TestEnrollCLIFailsClosedWhenEstablishedRootIsUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed bool
	}{
		{name: "verifier-only", seed: false},
		{name: "root custody", seed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			store := config.ProfileStore{Path: root, Secrets: config.FileSecretStore{Dir: filepath.Join(root, "secrets")}}
			issuer, accountID, endpointID := "https://api.example.test", "account_1", "cli_1"
			if tc.seed {
				keys, err := store.PeerIdentityKeys(issuer, accountID, endpointID)
				if err != nil {
					t.Fatal(err)
				}
				clearKeys(&keys)
			} else {
				public, _, err := ed25519.GenerateKey(nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.SavePeerAccountRootPublic(issuer, accountID, public); err != nil {
					t.Fatal(err)
				}
			}
			bootstrapped := false
			client := bootstrapClientFunc(func(context.Context, string, api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
				bootstrapped = true
				return api.E2EEBootstrapResult{}, nil
			})
			_, err := EnrollCLI(context.Background(), CLIRequest{Store: store, Client: client, Issuer: issuer, AccountID: accountID, CLIClientSessionID: endpointID})
			if !errors.Is(err, ErrEstablishedRootUnavailable) {
				t.Fatalf("err=%v", err)
			}
			if bootstrapped {
				t.Fatal("created a replacement root after server root disappeared")
			}
		})
	}
}

func TestBootstrapRejectsServerSubstitution(t *testing.T) {
	root := t.TempDir()
	store := config.ProfileStore{Path: root, Secrets: config.FileSecretStore{Dir: filepath.Join(root, "secrets")}}
	client := bootstrapClientFunc(func(_ context.Context, _ string, input api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
		input.Certificate.EndpointID = "other_cli"
		return bootstrapResult(input), nil
	})
	_, err := Bootstrap(context.Background(), Request{Store: store, Client: client, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_1", Now: func() time.Time { return time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC) }})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v", err)
	}
}

func TestBootstrapRequiresPairingWhenRemoteRootExistsWithoutLocalCustody(t *testing.T) {
	root := t.TempDir()
	store := config.ProfileStore{Path: root, Secrets: config.FileSecretStore{Dir: filepath.Join(root, "secrets")}}
	remotePublic, _, _ := ed25519.GenerateKey(nil)
	_, err := Bootstrap(context.Background(), Request{Store: store, Client: existingRootClient{root: rootDocument(remotePublic)}, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_1"})
	if !errors.Is(err, ErrPairingRequired) {
		t.Fatalf("err=%v", err)
	}
	entries, readErr := filepath.Glob(filepath.Join(root, "secrets", "*"))
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("secret entries=%v err=%v", entries, readErr)
	}
}

func TestValidateRemoteRootRejectsFingerprintAndCanonicalEncodingSubstitution(t *testing.T) {
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	valid := rootDocument(public)
	if got, err := validateRemoteRoot(valid); err != nil || len(got) != 1 || !bytes.Equal(got[0].PublicKey, public) {
		t.Fatalf("valid root rejected: %v", err)
	}
	cases := []api.E2EERoot{
		func() api.E2EERoot {
			v := valid
			v.TrustedKeys[0].Fingerprint = hex.EncodeToString(bytes.Repeat([]byte{0}, sha256.Size))
			return v
		}(),
		func() api.E2EERoot {
			v := valid
			v.TrustedKeys[0].PublicKey = base64.URLEncoding.EncodeToString(public)
			return v
		}(),
		func() api.E2EERoot { v := valid; v.TrustedKeys[0].Generation = 0; return v }(),
	}
	for index, candidate := range cases {
		if _, err := validateRemoteRoot(candidate); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d accepted substituted root: %v", index, err)
		}
	}
}

func rootKeyID(public ed25519.PublicKey) string {
	fingerprint := sha256.Sum256(public)
	return "aek_" + hex.EncodeToString(fingerprint[:])
}

func rootDocument(public ed25519.PublicKey) api.E2EERoot {
	fingerprint := sha256.Sum256(public)
	return api.E2EERoot{Version: 1, TrustedKeys: []api.E2EEKey{{KeyID: rootKeyID(public), PublicKey: base64.RawURLEncoding.EncodeToString(public), Fingerprint: hex.EncodeToString(fingerprint[:]), Generation: 1}}}
}

func bootstrapResult(input api.E2EEBootstrapInput) api.E2EEBootstrapResult {
	public, _ := base64.RawURLEncoding.DecodeString(input.RootPublicKey)
	root := rootDocument(ed25519.PublicKey(public))
	return api.E2EEBootstrapResult{KeyID: rootKeyID(ed25519.PublicKey(public)), TrustedKeys: root.TrustedKeys, Certificate: input.Certificate}
}
