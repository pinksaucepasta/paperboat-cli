// Package identitybootstrap creates and registers the first account-rooted CLI identity.
package identitybootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

const CertificateLifetime = 90 * 24 * time.Hour

var ErrInvalid = errors.New("invalid E2EE identity bootstrap")
var ErrPairingRequired = errors.New("this account already has an E2EE root; approval from a paired CLI or a recovery key is required")
var ErrEnrollmentExpired = errors.New("CLI endpoint enrollment request expired before approval")
var ErrEnrollmentDenied = errors.New("CLI endpoint enrollment request was denied")
var ErrEnrollmentRevoked = errors.New("CLI endpoint enrollment request was revoked")
var ErrEstablishedRootUnavailable = errors.New("this account has established E2EE state, but its server root is unavailable; explicit recovery is required")

type Client interface {
	E2EERoot(context.Context) (api.E2EERoot, error)
	BootstrapE2EE(context.Context, string, api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error)
}

// ExistingRootClient is the small control-plane surface needed to enroll a
// new CLI endpoint without ever possessing the account root private key.
type ExistingRootClient interface {
	E2EERoot(context.Context) (api.E2EERoot, error)
	RequestCLIEndpoint(context.Context, api.CLIEndpointRequestInput) (api.PendingEndpointIdentity, error)
	CLIEndpointRequestStatus(context.Context, string) (api.EndpointRequestStatus, error)
	EndpointCertificate(context.Context, string, uint64) (api.EndpointCertificateDocument, error)
}

// CLIClient is the complete control-plane surface used when a CLI session is
// being enrolled. A first account bootstraps its root; an existing account
// requests an endpoint certificate from a paired verifier.
type CLIClient interface {
	Client
	ExistingRootClient
}

type Request struct {
	Store              config.ProfileStore
	Client             Client
	Issuer             string
	AccountID          string
	CLIClientSessionID string
	Now                func() time.Time
}

type Result struct {
	RootFingerprint        string
	CertificateFingerprint string
	Certificate            endpointidentity.Certificate
}

type ExistingRootRequest struct {
	Store              config.ProfileStore
	Client             ExistingRootClient
	Issuer             string
	AccountID          string
	CLIClientSessionID string
	Now                func() time.Time
	PollInterval       time.Duration
	Timeout            time.Duration
}

type CLIRequest struct {
	Store              config.ProfileStore
	Client             CLIClient
	Issuer             string
	AccountID          string
	CLIClientSessionID string
	Now                func() time.Time
	PollInterval       time.Duration
	Timeout            time.Duration
}

// EnrollCLI selects the only valid enrollment ceremony for the account. An
// established root is never recreated or imported implicitly: the new CLI
// generates endpoint-only keys and waits for a paired verifier to approve
// them. Only an account with no root may execute the first-root bootstrap.
func EnrollCLI(ctx context.Context, request CLIRequest) (Result, error) {
	existing := ExistingRootRequest{
		Store: request.Store, Client: request.Client, Issuer: request.Issuer,
		AccountID: request.AccountID, CLIClientSessionID: request.CLIClientSessionID,
		Now: request.Now, PollInterval: request.PollInterval, Timeout: request.Timeout,
	}
	result, err := EnrollExistingRoot(ctx, existing)
	if err == nil || !api.IsNotFound(err) {
		return result, err
	}
	if established, stateErr := hasEstablishedRootState(request.Store, request.Issuer, request.AccountID); stateErr != nil {
		return Result{}, stateErr
	} else if established {
		return Result{}, ErrEstablishedRootUnavailable
	}
	return Bootstrap(ctx, Request{
		Store: request.Store, Client: request.Client, Issuer: request.Issuer,
		AccountID: request.AccountID, CLIClientSessionID: request.CLIClientSessionID,
		Now: request.Now,
	})
}

// hasEstablishedRootState distinguishes a genuinely new profile from one
// whose server root was removed or is temporarily unavailable. A verifier
// only profile stores the public key, while a recovery-capable profile also
// stores the root seed. Neither state may silently fall through to bootstrap
// and create a replacement account root.
func hasEstablishedRootState(store config.ProfileStore, issuer, accountID string) (bool, error) {
	if _, err := store.LoadPeerAccountRootPublic(issuer, accountID); err == nil {
		return true, nil
	} else if !errors.Is(err, config.ErrSecretNotFound) {
		return false, err
	}
	seed, err := store.ExportPeerAccountRootSeed(issuer, accountID)
	if err == nil {
		clear(seed)
		return true, nil
	}
	if !errors.Is(err, config.ErrSecretNotFound) {
		return false, err
	}
	return false, nil
}

// EnrollExistingRoot performs the second-device CLI enrollment handshake. It
// creates endpoint-only transport keys, asks the paired daemon to sign them,
// then verifies and persists the returned certificate and root public key.
// No root private key is loaded or generated in this path.
func EnrollExistingRoot(ctx context.Context, request ExistingRootRequest) (Result, error) {
	if ctx == nil || request.Client == nil || request.Store.Path == "" || request.Store.Secrets == nil || !boundedID(request.AccountID) || !boundedID(request.CLIClientSessionID) {
		return Result{}, ErrInvalid
	}
	started := time.Now()
	now := started.UTC()
	if request.Now != nil {
		now = request.Now().UTC()
	}
	now = now.Truncate(time.Second)
	root, err := request.Client.E2EERoot(ctx)
	if err != nil {
		return Result{}, err
	}
	rootPublic, rootFingerprint, err := validateRemoteRoot(root)
	if err != nil {
		return Result{}, err
	}
	defer clear(rootPublic)
	storedRoot, storedErr := request.Store.LoadPeerAccountRootPublic(request.Issuer, request.AccountID)
	if storedErr == nil {
		if !bytes.Equal(storedRoot, rootPublic) {
			clear(storedRoot)
			return Result{}, ErrInvalid
		}
		clear(storedRoot)
	} else if !errors.Is(storedErr, config.ErrSecretNotFound) {
		return Result{}, storedErr
	}
	keys, err := request.Store.PeerEndpointKeys(request.Issuer, request.AccountID, request.CLIClientSessionID)
	if err != nil {
		return Result{}, err
	}
	defer clearKeys(&keys)
	quicPublic, ok := keys.QUICPrivate.Public().(ed25519.PublicKey)
	if !ok || len(quicPublic) != ed25519.PublicKeySize || keys.NoisePublic == [32]byte{} {
		return Result{}, ErrInvalid
	}
	// A valid locally persisted certificate is the completed enrollment. In
	// particular, the first call may have bootstrapped the account root; a
	// later auth/login replay must not switch ceremonies and ask the server to
	// issue a second certificate for the same endpoint.
	local, localErr := request.Store.LoadPeerCertificate(request.Issuer, request.CLIClientSessionID)
	if localErr == nil {
		certificate, verifyErr := endpointidentity.Verify(local.Raw, rootPublic, endpointidentity.Expected{AccountID: request.AccountID, Role: endpointidentity.RoleCLI, EndpointID: request.CLIClientSessionID, Generation: 1}, now)
		certificateFingerprint := sha256.Sum256(local.Raw)
		matchesKeys := verifyErr == nil && certificate.Claims.NoisePublicKey == keys.NoisePublic && bytes.Equal(certificate.Claims.QUICPublicKey, quicPublic)
		clear(local.Raw)
		if !matchesKeys {
			return Result{}, ErrInvalid
		}
		return Result{RootFingerprint: hex.EncodeToString(rootFingerprint[:]), CertificateFingerprint: hex.EncodeToString(certificateFingerprint[:]), Certificate: certificate}, nil
	}
	if !errors.Is(localErr, config.ErrSecretNotFound) {
		return Result{}, localErr
	}
	operationID := existingEnrollmentOperationID(request.AccountID, request.CLIClientSessionID, keys.NoisePublic, quicPublic)
	pending, err := request.Client.RequestCLIEndpoint(ctx, api.CLIEndpointRequestInput{OperationID: operationID, EndpointID: request.CLIClientSessionID, Generation: 1, NoisePublicKey: base64.RawURLEncoding.EncodeToString(keys.NoisePublic[:]), QUICPublicKey: base64.RawURLEncoding.EncodeToString(quicPublic)})
	if err != nil {
		return Result{}, err
	}
	if err := validatePendingCLIEnrollment(pending, request.CLIClientSessionID, keys.NoisePublic, quicPublic, now); err != nil {
		return Result{}, err
	}
	interval := request.PollInterval
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	timeout := request.Timeout
	if timeout <= 0 {
		timeout = 6 * time.Minute
	}
	pollTimeout, err := enrollmentPollTimeout(pending, now, timeout, time.Since(started))
	if err != nil {
		return Result{}, err
	}
	pollCtx, cancel := context.WithTimeout(ctx, pollTimeout)
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		status, statusErr := request.Client.CLIEndpointRequestStatus(pollCtx, pending.RequestID)
		if statusErr != nil {
			// A successful request creation followed by an account-scoped not-found
			// cannot be safely treated as still pending: it is either inconsistent
			// server state or an account/request substitution.
			if api.IsNotFound(statusErr) {
				return Result{}, ErrInvalid
			}
			return Result{}, enrollmentPollError(ctx, pollCtx, statusErr)
		}
		if err := validateCLIEnrollmentStatus(status, pending, request.AccountID); err != nil {
			return Result{}, err
		}
		switch status.State {
		case "expired":
			return Result{}, ErrEnrollmentExpired
		case "denied":
			return Result{}, ErrEnrollmentDenied
		case "revoked":
			return Result{}, ErrEnrollmentRevoked
		case "pending":
			// Wait below before reading the next authoritative state.
		case "fulfilled":
			document, certErr := request.Client.EndpointCertificate(pollCtx, request.CLIClientSessionID, 1)
			if certErr != nil {
				if !api.IsNotFound(certErr) {
					return Result{}, enrollmentPollError(ctx, pollCtx, certErr)
				}
				break
			}
			current := time.Now().UTC()
			if request.Now != nil {
				current = request.Now().UTC()
			}
			current = current.Truncate(time.Second)
			remoteRoot, rootErr := request.Client.E2EERoot(pollCtx)
			if rootErr != nil {
				return Result{}, enrollmentPollError(ctx, pollCtx, rootErr)
			}
			verified, err := verifyEnrolledCLI(document, remoteRoot, rootPublic, rootFingerprint, request.AccountID, request.CLIClientSessionID, keys, current)
			if err != nil {
				return Result{}, err
			}
			if err := request.Store.SavePeerAccountRootPublic(request.Issuer, request.AccountID, rootPublic); err != nil {
				return Result{}, err
			}
			if _, err := request.Store.SavePeerCertificate(request.Issuer, request.CLIClientSessionID, verified.raw); err != nil {
				clear(verified.raw)
				return Result{}, err
			}
			clear(verified.raw)
			return Result{RootFingerprint: verified.rootFingerprint, CertificateFingerprint: verified.certificateFingerprint, Certificate: verified.certificate}, nil
		}
		select {
		case <-pollCtx.Done():
			if errors.Is(pollCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
				return Result{}, ErrEnrollmentExpired
			}
			return Result{}, pollCtx.Err()
		case <-ticker.C:
		}
	}
}

func enrollmentPollError(parent, poll context.Context, err error) error {
	if errors.Is(err, context.DeadlineExceeded) && errors.Is(poll.Err(), context.DeadlineExceeded) && parent.Err() == nil {
		return ErrEnrollmentExpired
	}
	return err
}

func enrollmentPollTimeout(pending api.PendingEndpointIdentity, now time.Time, configured, elapsed time.Duration) (time.Duration, error) {
	if configured <= 0 {
		return 0, ErrInvalid
	}
	if pending.State == "fulfilled" || pending.State == "expired" || pending.State == "denied" || pending.State == "revoked" {
		// The account-scoped status read remains authoritative for a replayed
		// terminal request, so retain a bounded window for that single read.
		return configured, nil
	}
	if pending.State != "pending" {
		return 0, ErrInvalid
	}
	issuedLifetime := pending.ExpiresAt.Sub(pending.CreatedAt)
	remaining := pending.ExpiresAt.Sub(now)
	if issuedLifetime <= 0 {
		return 0, ErrInvalid
	}
	// Never trust a client clock that would give the request more time than
	// its server-issued lifetime. Subtract local work already spent before the
	// polling context starts so setup latency cannot extend server expiry.
	if issuedLifetime < remaining {
		remaining = issuedLifetime
	}
	remaining -= elapsed
	if remaining <= 0 {
		return 0, ErrEnrollmentExpired
	}
	if remaining < configured {
		return remaining, nil
	}
	return configured, nil
}

type verifiedEnrollment struct {
	certificate            endpointidentity.Certificate
	raw                    []byte
	rootFingerprint        string
	certificateFingerprint string
}

func validateRemoteRoot(root api.E2EERoot) (ed25519.PublicKey, [sha256.Size]byte, error) {
	public, err := base64.RawURLEncoding.Strict().DecodeString(root.PublicKey)
	fingerprint := sha256.Sum256(public)
	if err != nil || len(public) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(public) != root.PublicKey || root.Version != 1 || root.Generation != 1 || root.Fingerprint != hex.EncodeToString(fingerprint[:]) {
		clear(public)
		return nil, [sha256.Size]byte{}, ErrInvalid
	}
	return ed25519.PublicKey(public), fingerprint, nil
}

func validatePendingCLIEnrollment(pending api.PendingEndpointIdentity, endpointID string, noise [32]byte, quic ed25519.PublicKey, now time.Time) error {
	if !boundedID(pending.RequestID) || pending.EndpointID != endpointID || pending.Role != "cli" || !validEnrollmentState(pending.State) || pending.Generation != 1 || pending.CreatedAt.After(now.Add(time.Minute)) {
		return ErrInvalid
	}
	// A fulfilled enrollment is deliberately replayable with the same bound
	// operation and public keys, even after its approval window has elapsed:
	// the caller must be able to recover an already-issued certificate after a
	// local persistence failure. A pending request still has a strict expiry.
	if pending.State == "pending" && !pending.ExpiresAt.After(now) {
		return ErrEnrollmentExpired
	}
	expectedNoise := base64.RawURLEncoding.EncodeToString(noise[:])
	expectedQUIC := base64.RawURLEncoding.EncodeToString(quic)
	if pending.NoisePublicKey != expectedNoise || pending.QUICPublicKey != expectedQUIC || pending.NoisePublicKey == "" || pending.QUICPublicKey == "" {
		return ErrInvalid
	}
	return nil
}

func validEnrollmentState(state string) bool {
	switch state {
	case "pending", "fulfilled", "expired", "denied", "revoked":
		return true
	default:
		return false
	}
}

func validateCLIEnrollmentStatus(status api.EndpointRequestStatus, pending api.PendingEndpointIdentity, accountID string) error {
	if status.RequestID != pending.RequestID || status.AccountID != accountID || status.EndpointID != pending.EndpointID ||
		status.Role != pending.Role || status.Generation != pending.Generation || status.NoisePublicKey != pending.NoisePublicKey ||
		status.QUICPublicKey != pending.QUICPublicKey || !status.CreatedAt.Equal(pending.CreatedAt) ||
		!status.ExpiresAt.Equal(pending.ExpiresAt) || status.SafetyCode != pending.SafetyCode {
		return ErrInvalid
	}
	if validEnrollmentState(status.State) {
		return nil
	}
	return ErrInvalid
}

func verifyEnrolledCLI(document api.EndpointCertificateDocument, remoteRoot api.E2EERoot, rootPublic ed25519.PublicKey, rootFingerprint [sha256.Size]byte, accountID, endpointID string, keys config.PeerIdentityKeys, now time.Time) (verifiedEnrollment, error) {
	remotePublic, remoteFingerprint, err := validateRemoteRoot(remoteRoot)
	if err != nil || !bytes.Equal(remotePublic, rootPublic) || remoteFingerprint != rootFingerprint {
		clear(remotePublic)
		return verifiedEnrollment{}, ErrInvalid
	}
	clear(remotePublic)
	raw, err := base64.RawURLEncoding.Strict().DecodeString(document.Certificate)
	certificateFingerprint := sha256.Sum256(raw)
	quicPublic, ok := keys.QUICPrivate.Public().(ed25519.PublicKey)
	if !ok {
		clear(raw)
		return verifiedEnrollment{}, ErrInvalid
	}
	certificate, verifyErr := endpointidentity.Verify(raw, rootPublic, endpointidentity.Expected{AccountID: accountID, Role: endpointidentity.RoleCLI, EndpointID: endpointID, Generation: 1}, now)
	if err != nil || len(raw) == 0 || base64.RawURLEncoding.EncodeToString(raw) != document.Certificate || verifyErr != nil || document.Version != 1 || document.AccountID != accountID || document.RootFingerprint != hex.EncodeToString(rootFingerprint[:]) || document.EndpointID != endpointID || document.Role != "cli" || document.Generation != 1 || document.Serial != certificate.Claims.Serial || document.IssuedAt != certificate.Claims.IssuedAt.Format(time.RFC3339) || document.ExpiresAt != certificate.Claims.ExpiresAt.Format(time.RFC3339) || document.CertificateFingerprint != hex.EncodeToString(certificateFingerprint[:]) || certificate.Claims.NoisePublicKey != keys.NoisePublic || !bytes.Equal(certificate.Claims.QUICPublicKey, quicPublic) {
		clear(raw)
		return verifiedEnrollment{}, ErrInvalid
	}
	return verifiedEnrollment{certificate: certificate, raw: raw, rootFingerprint: document.RootFingerprint, certificateFingerprint: document.CertificateFingerprint}, nil
}

func existingEnrollmentOperationID(accountID, endpointID string, noise [32]byte, quic ed25519.PublicKey) string {
	hash := sha256.New()
	hash.Write([]byte("paperboat-cli-endpoint-v1\x00"))
	hash.Write([]byte(accountID))
	hash.Write([]byte("\x00"))
	hash.Write([]byte(endpointID))
	hash.Write([]byte("\x00"))
	hash.Write(noise[:])
	hash.Write(quic)
	return "op_peer_cli_enroll_" + hex.EncodeToString(hash.Sum(nil)[:16])
}

func Bootstrap(ctx context.Context, request Request) (Result, error) {
	if ctx == nil || request.Client == nil || request.Store.Path == "" || request.Store.Secrets == nil || !boundedID(request.AccountID) || !boundedID(request.CLIClientSessionID) {
		return Result{}, ErrInvalid
	}
	now := time.Now().UTC()
	if request.Now != nil {
		now = request.Now().UTC()
	}
	now = now.Truncate(time.Second)
	remoteRoot, rootErr := request.Client.E2EERoot(ctx)
	rootExists := rootErr == nil
	if rootErr != nil && !api.IsNotFound(rootErr) {
		return Result{}, rootErr
	}
	var keys config.PeerIdentityKeys
	var err error
	if rootExists {
		keys, err = request.Store.PeerIdentityKeysForExistingRoot(request.Issuer, request.AccountID, request.CLIClientSessionID)
		if errors.Is(err, config.ErrSecretNotFound) {
			return Result{}, ErrPairingRequired
		}
	} else {
		keys, err = request.Store.PeerIdentityKeys(request.Issuer, request.AccountID, request.CLIClientSessionID)
	}
	if err != nil {
		return Result{}, err
	}
	defer clearKeys(&keys)
	rootPublic, ok := keys.RootPrivate.Public().(ed25519.PublicKey)
	if !ok || len(rootPublic) != ed25519.PublicKeySize {
		return Result{}, ErrInvalid
	}
	if rootExists {
		remotePublic, decodeErr := base64.RawURLEncoding.Strict().DecodeString(remoteRoot.PublicKey)
		remoteFingerprint := sha256.Sum256(rootPublic)
		if decodeErr != nil || len(remotePublic) != ed25519.PublicKeySize || !bytes.Equal(remotePublic, rootPublic) || remoteRoot.Version != 1 || remoteRoot.Generation != 1 || remoteRoot.Fingerprint != hex.EncodeToString(remoteFingerprint[:]) {
			clear(remotePublic)
			return Result{}, ErrInvalid
		}
		clear(remotePublic)
	}
	certificate, raw, err := loadOrCreateCertificate(request, keys, rootPublic, now)
	if err != nil {
		return Result{}, err
	}
	rootFingerprint := sha256.Sum256(rootPublic)
	certificateFingerprint := sha256.Sum256(raw)
	operationID := "op_peer_bootstrap_" + hex.EncodeToString(certificateFingerprint[:16])
	document := api.EndpointCertificateDocument{Version: 1, AccountID: request.AccountID, RootFingerprint: hex.EncodeToString(rootFingerprint[:]), EndpointID: request.CLIClientSessionID, Role: "cli", Generation: certificate.Claims.Generation, Serial: certificate.Claims.Serial, IssuedAt: certificate.Claims.IssuedAt.Format(time.RFC3339), ExpiresAt: certificate.Claims.ExpiresAt.Format(time.RFC3339), Certificate: base64.RawURLEncoding.EncodeToString(raw), CertificateFingerprint: hex.EncodeToString(certificateFingerprint[:])}
	response, err := request.Client.BootstrapE2EE(ctx, operationID, api.E2EEBootstrapInput{RootPublicKey: base64.RawURLEncoding.EncodeToString(rootPublic), Certificate: document})
	if err != nil {
		return Result{}, err
	}
	if response.RootPublicKey != base64.RawURLEncoding.EncodeToString(rootPublic) || response.Certificate != document {
		return Result{}, ErrInvalid
	}
	return Result{RootFingerprint: document.RootFingerprint, CertificateFingerprint: document.CertificateFingerprint, Certificate: certificate}, nil
}

func loadOrCreateCertificate(request Request, keys config.PeerIdentityKeys, rootPublic ed25519.PublicKey, now time.Time) (endpointidentity.Certificate, []byte, error) {
	state, err := request.Store.LoadPeerCertificate(request.Issuer, request.CLIClientSessionID)
	if err == nil {
		certificate, verifyErr := endpointidentity.Verify(state.Raw, rootPublic, endpointidentity.Expected{AccountID: request.AccountID, Role: endpointidentity.RoleCLI, EndpointID: request.CLIClientSessionID, Generation: 1}, now)
		if verifyErr != nil || certificate.Claims.NoisePublicKey != keys.NoisePublic || !bytes.Equal(certificate.Claims.QUICPublicKey, keys.QUICPrivate.Public().(ed25519.PublicKey)) {
			clear(state.Raw)
			return endpointidentity.Certificate{}, nil, ErrInvalid
		}
		return certificate, state.Raw, nil
	}
	if !errors.Is(err, config.ErrSecretNotFound) {
		return endpointidentity.Certificate{}, nil, err
	}
	quicPublic := keys.QUICPrivate.Public().(ed25519.PublicKey)
	certificate, err := endpointidentity.Sign(keys.RootPrivate, endpointidentity.Claims{AccountID: request.AccountID, Role: endpointidentity.RoleCLI, EndpointID: request.CLIClientSessionID, NoisePublicKey: keys.NoisePublic, QUICPublicKey: quicPublic, Generation: 1, Serial: 1, IssuedAt: now, ExpiresAt: now.Add(CertificateLifetime)})
	if err != nil {
		return endpointidentity.Certificate{}, nil, err
	}
	raw, err := certificate.MarshalBinary()
	if err != nil {
		return endpointidentity.Certificate{}, nil, err
	}
	state, err = request.Store.SavePeerCertificate(request.Issuer, request.CLIClientSessionID, raw)
	if err != nil {
		clear(raw)
		return endpointidentity.Certificate{}, nil, err
	}
	clear(raw)
	return certificate, state.Raw, nil
}

func boundedID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character == 0 || character == '\r' || character == '\n' || character == ' ' {
			return false
		}
	}
	return true
}

func clearKeys(keys *config.PeerIdentityKeys) {
	if keys == nil {
		return
	}
	clear(keys.RootPrivate)
	clear(keys.NoisePrivate[:])
	clear(keys.NoisePublic[:])
	clear(keys.QUICPrivate)
	*keys = config.PeerIdentityKeys{}
}
