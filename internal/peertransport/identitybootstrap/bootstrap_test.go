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
func (bootstrapClientFunc) RequestCLIEndpoint(context.Context, api.CLIEndpointRequestInput) (api.PendingEndpointIdentity, error) {
	return api.PendingEndpointIdentity{}, errors.New("existing-root enrollment must not run")
}
func (bootstrapClientFunc) CLIEndpointRequestStatus(context.Context, string) (api.EndpointRequestStatus, error) {
	return api.EndpointRequestStatus{}, errors.New("existing-root enrollment must not run")
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
	if c.root.PublicKey == "" {
		return api.E2EERoot{}, &api.APIError{Status: http.StatusNotFound, Code: "not_found"}
	}
	return c.root, nil
}

func (c *newRootReplayClient) BootstrapE2EE(ctx context.Context, operation string, input api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
	result, err := c.bootstrap(ctx, operation, input)
	if err == nil {
		public, decodeErr := base64.RawURLEncoding.Strict().DecodeString(input.RootPublicKey)
		fingerprint := sha256.Sum256(public)
		if decodeErr != nil {
			return api.E2EEBootstrapResult{}, decodeErr
		}
		c.root = api.E2EERoot{Version: 1, PublicKey: input.RootPublicKey, Fingerprint: hex.EncodeToString(fingerprint[:]), Generation: 1}
	}
	return result, err
}

func (c *newRootReplayClient) RequestCLIEndpoint(context.Context, api.CLIEndpointRequestInput) (api.PendingEndpointIdentity, error) {
	c.requests++
	return api.PendingEndpointIdentity{}, errors.New("completed first-root enrollment must not request another certificate")
}

func (*newRootReplayClient) CLIEndpointRequestStatus(context.Context, string) (api.EndpointRequestStatus, error) {
	return api.EndpointRequestStatus{}, errors.New("completed first-root enrollment must not poll request status")
}

func (*newRootReplayClient) EndpointCertificate(context.Context, string, uint64) (api.EndpointCertificateDocument, error) {
	return api.EndpointCertificateDocument{}, errors.New("completed first-root enrollment must not poll another certificate")
}

type existingEnrollmentClient struct {
	root        api.E2EERoot
	pending     api.PendingEndpointIdentity
	status      api.EndpointRequestStatus
	statuses    []api.EndpointRequestStatus
	statusErr   error
	certificate api.EndpointCertificateDocument
	requests    int
	statusReads int
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
func (c *existingEnrollmentClient) CLIEndpointRequestStatus(_ context.Context, requestID string) (api.EndpointRequestStatus, error) {
	c.statusReads++
	if requestID != c.pending.RequestID {
		return api.EndpointRequestStatus{}, errors.New("status request identity mismatch")
	}
	if c.statusErr != nil {
		return api.EndpointRequestStatus{}, c.statusErr
	}
	if len(c.statuses) != 0 {
		index := c.statusReads - 1
		if index >= len(c.statuses) {
			index = len(c.statuses) - 1
		}
		return c.statuses[index], nil
	}
	if c.status.RequestID != "" {
		return c.status, nil
	}
	state := c.pending.State
	if c.certificate.Certificate != "" {
		state = "fulfilled"
	}
	return api.EndpointRequestStatus{
		RequestID: c.pending.RequestID, AccountID: "account_1", EndpointID: c.pending.EndpointID,
		Role: c.pending.Role, Generation: c.pending.Generation, NoisePublicKey: c.pending.NoisePublicKey,
		QUICPublicKey: c.pending.QUICPublicKey, CreatedAt: c.pending.CreatedAt, ExpiresAt: c.pending.ExpiresAt,
		SafetyCode: c.pending.SafetyCode, State: state,
	}, nil
}

func endpointRequestStatus(pending api.PendingEndpointIdentity, accountID, state string) api.EndpointRequestStatus {
	return api.EndpointRequestStatus{
		RequestID: pending.RequestID, AccountID: accountID, EndpointID: pending.EndpointID,
		Role: pending.Role, Generation: pending.Generation, NoisePublicKey: pending.NoisePublicKey,
		QUICPublicKey: pending.QUICPublicKey, CreatedAt: pending.CreatedAt, ExpiresAt: pending.ExpiresAt,
		SafetyCode: pending.SafetyCode, State: state,
	}
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

func TestEnrollmentPollTimeoutCapsToAuthoritativeExpiryAndIssuedLifetime(t *testing.T) {
	serverNow := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	pending := api.PendingEndpointIdentity{State: "pending", CreatedAt: serverNow, ExpiresAt: serverNow.Add(2 * time.Minute)}
	if got, err := enrollmentPollTimeout(pending, serverNow, 10*time.Minute, 5*time.Second); err != nil || got != 115*time.Second {
		t.Fatalf("authoritative expiry cap=%s err=%v", got, err)
	}
	// A client clock behind the server must not grant more than the complete
	// server-issued request lifetime from the time the response is received.
	if got, err := enrollmentPollTimeout(pending, serverNow.Add(-time.Hour), 10*time.Minute, 5*time.Second); err != nil || got != 115*time.Second {
		t.Fatalf("skew-safe issued-lifetime cap=%s err=%v", got, err)
	}
	if _, err := enrollmentPollTimeout(pending, serverNow.Add(3*time.Minute), 10*time.Minute, 0); !errors.Is(err, ErrEnrollmentExpired) {
		t.Fatalf("expired request err=%v", err)
	}
	fulfilled := pending
	fulfilled.State = "fulfilled"
	fulfilled.ExpiresAt = serverNow.Add(-time.Minute)
	if got, err := enrollmentPollTimeout(fulfilled, serverNow, time.Minute, 0); err != nil || got != time.Minute {
		t.Fatalf("fulfilled recovery timeout=%s err=%v", got, err)
	}
}

func TestEnrollExistingRootConsumesTerminalRequestStates(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		state string
		err   error
	}{{"expired", ErrEnrollmentExpired}, {"denied", ErrEnrollmentDenied}, {"revoked", ErrEnrollmentRevoked}} {
		t.Run(tc.state, func(t *testing.T) {
			client, request, _ := newExistingEnrollmentFixture(t, now)
			client.pending.State = tc.state
			if tc.state == "expired" {
				client.pending.CreatedAt = now.Add(-2 * time.Minute)
				client.pending.ExpiresAt = now.Add(-time.Minute)
			}
			client.status = endpointRequestStatus(client.pending, request.AccountID, tc.state)
			_, err := EnrollExistingRoot(context.Background(), request)
			if !errors.Is(err, tc.err) || client.requests != 1 || client.statusReads != 1 || client.certReads != 0 {
				t.Fatalf("requests=%d status=%d certificates=%d err=%v", client.requests, client.statusReads, client.certReads, err)
			}
		})
	}
}

func TestEnrollExistingRootRejectsStatusSubstitutionAndAccountScopedNotFound(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	for _, mutate := range []func(*api.EndpointRequestStatus){
		func(status *api.EndpointRequestStatus) { status.AccountID = "account_other" },
		func(status *api.EndpointRequestStatus) { status.RequestID = "per_substituted" },
		func(status *api.EndpointRequestStatus) { status.EndpointID = "cli_other" },
		func(status *api.EndpointRequestStatus) {
			status.NoisePublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		},
	} {
		client, request, _ := newExistingEnrollmentFixture(t, now)
		status := endpointRequestStatus(client.pending, request.AccountID, "fulfilled")
		mutate(&status)
		client.status = status
		if _, err := EnrollExistingRoot(context.Background(), request); !errors.Is(err, ErrInvalid) {
			t.Fatalf("substituted status accepted: %+v err=%v", status, err)
		}
		if client.certReads != 0 {
			t.Fatalf("certificate fetched after status substitution: %d", client.certReads)
		}
	}
	client, request, _ := newExistingEnrollmentFixture(t, now)
	client.statusErr = &api.APIError{Status: http.StatusNotFound, Code: "not_found"}
	if _, err := EnrollExistingRoot(context.Background(), request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("account-scoped not-found was not fail-closed: %v", err)
	}
}

func TestEnrollExistingRootRetriesPendingStatusThenRecoversFulfilledCertificate(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	client, request, certificate := newExistingEnrollmentFixture(t, now)
	client.certificate = certificate
	client.statuses = []api.EndpointRequestStatus{
		endpointRequestStatus(client.pending, request.AccountID, "pending"),
		endpointRequestStatus(client.pending, request.AccountID, "fulfilled"),
	}
	result, err := EnrollExistingRoot(context.Background(), request)
	if err != nil || result.CertificateFingerprint != certificate.CertificateFingerprint || client.requests != 1 || client.statusReads != 2 || client.certReads != 1 {
		t.Fatalf("result=%+v requests=%d status=%d certificates=%d err=%v", result, client.requests, client.statusReads, client.certReads, err)
	}
	// The persisted result is the idempotency boundary: replay performs no
	// request, status, or certificate network operation.
	if _, err := EnrollExistingRoot(context.Background(), request); err != nil || client.requests != 1 || client.statusReads != 2 || client.certReads != 1 {
		t.Fatalf("local replay requests=%d status=%d certificates=%d err=%v", client.requests, client.statusReads, client.certReads, err)
	}
	if _, err := request.Store.ExportPeerAccountRootSeed(request.Issuer, request.AccountID); !errors.Is(err, config.ErrSecretNotFound) {
		t.Fatalf("existing account root private key was imported: %v", err)
	}
}

func newExistingEnrollmentFixture(t *testing.T, now time.Time) (*existingEnrollmentClient, ExistingRootRequest, api.EndpointCertificateDocument) {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rootFingerprint := sha256.Sum256(rootPublic)
	rootDir := t.TempDir()
	store := config.ProfileStore{Path: rootDir, Secrets: config.FileSecretStore{Dir: filepath.Join(rootDir, "secrets")}}
	keys, err := store.PeerEndpointKeys("https://api.example.test", "account_1", "cli_1")
	if err != nil {
		t.Fatal(err)
	}
	quicPublic := keys.QUICPrivate.Public().(ed25519.PublicKey)
	pending := api.PendingEndpointIdentity{
		RequestID: "per_0123456789abcdef", EndpointID: "cli_1", Role: "cli", State: "pending", Generation: 1,
		NoisePublicKey: base64.RawURLEncoding.EncodeToString(keys.NoisePublic[:]), QUICPublicKey: base64.RawURLEncoding.EncodeToString(quicPublic),
		CreatedAt: now, ExpiresAt: now.Add(time.Minute), SafetyCode: "abcde-fghij",
	}
	certificate, err := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{
		AccountID: "account_1", Role: endpointidentity.RoleCLI, EndpointID: "cli_1", NoisePublicKey: keys.NoisePublic,
		QUICPublicKey: quicPublic, Generation: 1, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	})
	clearKeys(&keys)
	clear(rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := certificate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	certificateFingerprint := sha256.Sum256(raw)
	document := api.EndpointCertificateDocument{
		Version: 1, AccountID: "account_1", RootFingerprint: hex.EncodeToString(rootFingerprint[:]), EndpointID: "cli_1", Role: "cli",
		Generation: 1, Serial: 1, IssuedAt: certificate.Claims.IssuedAt.Format(time.RFC3339), ExpiresAt: certificate.Claims.ExpiresAt.Format(time.RFC3339),
		Certificate: base64.RawURLEncoding.EncodeToString(raw), CertificateFingerprint: hex.EncodeToString(certificateFingerprint[:]),
	}
	clear(raw)
	client := &existingEnrollmentClient{root: api.E2EERoot{Version: 1, PublicKey: base64.RawURLEncoding.EncodeToString(rootPublic), Fingerprint: hex.EncodeToString(rootFingerprint[:]), Generation: 1}, pending: pending}
	request := ExistingRootRequest{Store: store, Client: client, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_1", Now: func() time.Time { return now }, PollInterval: time.Millisecond, Timeout: time.Second}
	return client, request, document
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
		return api.E2EEBootstrapResult(input), nil
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
