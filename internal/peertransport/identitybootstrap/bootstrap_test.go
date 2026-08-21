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

func (bootstrapClientFunc) E2EERoot(context.Context) (api.E2EERoot, error) {
	return api.E2EERoot{}, &api.APIError{Status: 404, Code: "not_found"}
}

type existingRootClient struct{ root api.E2EERoot }

func (c existingRootClient) E2EERoot(context.Context) (api.E2EERoot, error) { return c.root, nil }
func (existingRootClient) BootstrapE2EE(context.Context, string, api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
	return api.E2EEBootstrapResult{}, errors.New("bootstrap must not run before pairing")
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

func TestEnrollExistingRootStoresVerifierOnlyIdentityAndIsIdempotent(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(nil)
	rootFingerprint := sha256.Sum256(rootPublic)
	root := api.E2EERoot{Version: 1, PublicKey: base64.RawURLEncoding.EncodeToString(rootPublic), Fingerprint: hex.EncodeToString(rootFingerprint[:]), Generation: 1}
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
	client := &existingEnrollmentClient{root: root, pending: api.PendingEndpointIdentity{RequestID: "per_0123456789abcdef", EndpointID: "cli_1", Role: "cli", State: "pending", Generation: 1, NoisePublicKey: base64.RawURLEncoding.EncodeToString(keys.NoisePublic[:]), QUICPublicKey: base64.RawURLEncoding.EncodeToString(quicPublic), CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(4 * time.Minute), SafetyCode: "abcde-fghij"}, certificate: api.EndpointCertificateDocument{Version: 1, AccountID: "account_1", RootFingerprint: hex.EncodeToString(rootFingerprint[:]), EndpointID: "cli_1", Role: "cli", Generation: 1, Serial: 1, IssuedAt: certificate.Claims.IssuedAt.Format(time.RFC3339), ExpiresAt: certificate.Claims.ExpiresAt.Format(time.RFC3339), Certificate: base64.RawURLEncoding.EncodeToString(raw), CertificateFingerprint: hex.EncodeToString(certificateFingerprint[:])}}
	request := ExistingRootRequest{Store: store, Client: client, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_1", Now: func() time.Time { return now }, PollInterval: time.Millisecond, Timeout: time.Second}
	first, err := EnrollExistingRoot(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EnrollExistingRoot(context.Background(), request)
	if err != nil || first.RootFingerprint != second.RootFingerprint || first.CertificateFingerprint != second.CertificateFingerprint || client.requests != 2 {
		t.Fatalf("first=%+v second=%+v requests=%d err=%v", first, second, client.requests, err)
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
	rootFingerprint := sha256.Sum256(rootPublic)
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
		root:        api.E2EERoot{Version: 1, PublicKey: base64.RawURLEncoding.EncodeToString(rootPublic), Fingerprint: hex.EncodeToString(rootFingerprint[:]), Generation: 1},
		pending:     api.PendingEndpointIdentity{RequestID: "per_0123456789abcdef", EndpointID: "cli_1", Role: "cli", State: "fulfilled", Generation: 1, NoisePublicKey: base64.RawURLEncoding.EncodeToString(keys.NoisePublic[:]), QUICPublicKey: base64.RawURLEncoding.EncodeToString(quicPublic), CreatedAt: now.Add(-10 * time.Minute), ExpiresAt: now.Add(-5 * time.Minute), SafetyCode: "abcde-fghij"},
		certificate: api.EndpointCertificateDocument{Version: 1, AccountID: "account_1", RootFingerprint: hex.EncodeToString(rootFingerprint[:]), EndpointID: "cli_1", Role: "cli", Generation: 1, Serial: 1, IssuedAt: certificate.Claims.IssuedAt.Format(time.RFC3339), ExpiresAt: certificate.Claims.ExpiresAt.Format(time.RFC3339), Certificate: base64.RawURLEncoding.EncodeToString(raw), CertificateFingerprint: hex.EncodeToString(certificateFingerprint[:])},
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
	rootFingerprint := sha256.Sum256(rootPublic)
	rootDir := t.TempDir()
	store := config.ProfileStore{Path: rootDir, Secrets: config.FileSecretStore{Dir: filepath.Join(rootDir, "secrets")}}
	keys, err := store.PeerEndpointKeys("https://api.example.test", "account_1", "cli_1")
	if err != nil {
		t.Fatal(err)
	}
	quicPublic := keys.QUICPrivate.Public().(ed25519.PublicKey)
	client := &existingEnrollmentClient{root: api.E2EERoot{Version: 1, PublicKey: base64.RawURLEncoding.EncodeToString(rootPublic), Fingerprint: hex.EncodeToString(rootFingerprint[:]), Generation: 1}, pending: api.PendingEndpointIdentity{RequestID: "per_0123456789abcdef", EndpointID: "cli_1", Role: "cli", State: "pending", Generation: 1, NoisePublicKey: base64.RawURLEncoding.EncodeToString(keys.NoisePublic[:]), QUICPublicKey: base64.RawURLEncoding.EncodeToString(quicPublic), CreatedAt: now, ExpiresAt: now.Add(time.Minute), SafetyCode: "abcde-fghij"}}
	err = nil
	_, err = EnrollExistingRoot(context.Background(), ExistingRootRequest{Store: store, Client: client, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_1", Now: func() time.Time { return now }, PollInterval: time.Millisecond, Timeout: 10 * time.Millisecond})
	if !errors.Is(err, ErrEnrollmentExpired) {
		t.Fatalf("err=%v", err)
	}
}

func (f bootstrapClientFunc) BootstrapE2EE(ctx context.Context, operation string, input api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
	return f(ctx, operation, input)
}

func TestBootstrapCreatesPersistsAndExactlyReplaysCLIIdentity(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	store := config.ProfileStore{Path: root, Secrets: config.FileSecretStore{Dir: filepath.Join(root, "secrets")}}
	var firstOperation string
	var firstInput api.E2EEBootstrapInput
	client := bootstrapClientFunc(func(_ context.Context, operation string, input api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
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
		return api.E2EEBootstrapResult(input), nil
	})
	request := Request{Store: store, Client: client, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_1", Now: func() time.Time { return now }}
	first, err := Bootstrap(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Bootstrap(context.Background(), request)
	if err != nil || first.RootFingerprint != second.RootFingerprint || first.CertificateFingerprint != second.CertificateFingerprint {
		t.Fatalf("first=%+v second=%+v err=%v", first, second, err)
	}
}

func TestBootstrapRejectsServerSubstitution(t *testing.T) {
	root := t.TempDir()
	store := config.ProfileStore{Path: root, Secrets: config.FileSecretStore{Dir: filepath.Join(root, "secrets")}}
	client := bootstrapClientFunc(func(_ context.Context, _ string, input api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
		input.Certificate.EndpointID = "other_cli"
		return api.E2EEBootstrapResult(input), nil
	})
	_, err := Bootstrap(context.Background(), Request{Store: store, Client: client, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_1", Now: func() time.Time { return time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC) }})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v", err)
	}
}

func TestBootstrapRequiresPairingWhenRemoteRootExistsWithoutLocalCustody(t *testing.T) {
	root := t.TempDir()
	store := config.ProfileStore{Path: root, Secrets: config.FileSecretStore{Dir: filepath.Join(root, "secrets")}}
	_, err := Bootstrap(context.Background(), Request{Store: store, Client: existingRootClient{root: api.E2EERoot{Version: 1, PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Generation: 1}}, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_1"})
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
	fingerprint := sha256.Sum256(public)
	valid := api.E2EERoot{Version: 1, PublicKey: base64.RawURLEncoding.EncodeToString(public), Fingerprint: hex.EncodeToString(fingerprint[:]), Generation: 1}
	if got, _, err := validateRemoteRoot(valid); err != nil || !bytes.Equal(got, public) {
		t.Fatalf("valid root rejected: %v", err)
	}
	cases := []api.E2EERoot{
		func() api.E2EERoot {
			v := valid
			v.Fingerprint = hex.EncodeToString(bytes.Repeat([]byte{0}, sha256.Size))
			return v
		}(),
		func() api.E2EERoot { v := valid; v.PublicKey = base64.URLEncoding.EncodeToString(public); return v }(),
		func() api.E2EERoot { v := valid; v.Generation = 2; return v }(),
	}
	for index, candidate := range cases {
		if _, _, err := validateRemoteRoot(candidate); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d accepted substituted root: %v", index, err)
		}
	}
}
