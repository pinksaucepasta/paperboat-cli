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
	"github.com/pinksaucepasta/paperboat/internal/peertransport/trustedkeys"
)

const (
	CertificateLifetime = 90 * 24 * time.Hour
	// New endpoint certificates are backdated by the contract's bounded clock
	// skew so a client whose wall clock is slightly ahead of the control plane
	// can enroll. Expiry remains anchored to the observed client time and is
	// still checked strictly by every verifier.
	CertificateClockSkew = time.Minute
)

var ErrInvalid = errors.New("invalid E2EE identity bootstrap")
var ErrPairingRequired = errors.New("this account already has an E2EE root; approval from a paired CLI or a recovery key is required")
var ErrEnrollmentExpired = errors.New("CLI endpoint enrollment request expired before approval")
var ErrEstablishedRootUnavailable = errors.New("this account has established E2EE state, but its server root is unavailable; explicit recovery is required")

type invalidResponseError struct{ Stage string }

func (e invalidResponseError) Error() string {
	return "invalid E2EE identity bootstrap response: " + e.Stage
}
func (e invalidResponseError) Unwrap() error { return ErrInvalid }

type Client interface {
	E2EERoot(context.Context) (api.E2EERoot, error)
	BootstrapE2EE(context.Context, string, api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error)
}

type FreshClient interface {
	BootstrapE2EEFresh(context.Context, string, api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error)
}

// ExistingRootClient is the small control-plane surface needed to enroll a
// new CLI endpoint without ever possessing the account root private key.
type ExistingRootClient interface {
	E2EERoot(context.Context) (api.E2EERoot, error)
	RequestCLIEndpoint(context.Context, api.CLIEndpointRequestInput) (api.PendingEndpointIdentity, error)
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
	Store                config.ProfileStore
	Client               Client
	Issuer               string
	AccountID            string
	CLIClientSessionID   string
	Now                  func() time.Time
	AllowRootReplacement bool
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
	Fresh              bool
}

// EnrollCLI selects the enrollment ceremony for the account. A dashboard
// enrollment is a deliberate fresh install: it replaces any local identity
// and uses the one-shot authorization to bootstrap a new account root without
// requiring another endpoint to approve the machine.
func EnrollCLI(ctx context.Context, request CLIRequest) (Result, error) {
	existing := ExistingRootRequest{
		Store: request.Store, Client: request.Client, Issuer: request.Issuer,
		AccountID: request.AccountID, CLIClientSessionID: request.CLIClientSessionID,
		Now: request.Now, PollInterval: request.PollInterval, Timeout: request.Timeout,
	}
	if request.Fresh {
		return Bootstrap(ctx, Request{Store: request.Store, Client: request.Client, Issuer: request.Issuer, AccountID: request.AccountID, CLIClientSessionID: request.CLIClientSessionID, Now: request.Now, AllowRootReplacement: true})
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
	now := time.Now().UTC()
	if request.Now != nil {
		now = request.Now().UTC()
	}
	now = now.Truncate(time.Second)
	root, err := request.Client.E2EERoot(ctx)
	if err != nil {
		return Result{}, err
	}
	trusted, err := validateRemoteRoot(root)
	if err != nil {
		return Result{}, err
	}
	defer trustedkeys.Clear(trusted)
	storedRoot, storedErr := request.Store.LoadPeerAccountRootPublic(request.Issuer, request.AccountID)
	if storedErr == nil {
		if _, ok := trustedkeys.ByPublic(trusted, storedRoot); !ok {
			clear(storedRoot)
			return Result{}, ErrInvalid
		}
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
	localKey, ok := trustedkeys.ByPublic(trusted, storedRoot)
	clear(storedRoot)
	if storedErr == nil && !ok {
		return Result{}, ErrInvalid
	}
	// A valid locally persisted certificate is the completed enrollment. In
	// particular, the first call may have bootstrapped the account root; a
	// later auth/login replay must not switch ceremonies and ask the server to
	// issue a second certificate for the same endpoint.
	local, localErr := request.Store.LoadPeerCertificate(request.Issuer, request.CLIClientSessionID)
	if localErr == nil {
		var certificate endpointidentity.Certificate
		var verifyErr error
		if !ok {
			for _, candidate := range trusted {
				certificate, verifyErr = endpointidentity.Verify(local.Raw, candidate.PublicKey, endpointidentity.Expected{AccountID: request.AccountID, Role: endpointidentity.RoleCLI, EndpointID: request.CLIClientSessionID, Generation: 1}, now)
				if verifyErr == nil {
					localKey, ok = candidate, true
					break
				}
			}
		} else {
			certificate, verifyErr = endpointidentity.Verify(local.Raw, localKey.PublicKey, endpointidentity.Expected{AccountID: request.AccountID, Role: endpointidentity.RoleCLI, EndpointID: request.CLIClientSessionID, Generation: 1}, now)
		}
		certificateFingerprint := sha256.Sum256(local.Raw)
		matchesKeys := verifyErr == nil && certificate.Claims.NoisePublicKey == keys.NoisePublic && bytes.Equal(certificate.Claims.QUICPublicKey, quicPublic)
		clear(local.Raw)
		if !matchesKeys {
			return Result{}, ErrInvalid
		}
		return Result{RootFingerprint: trustedkeys.FingerprintString(localKey), CertificateFingerprint: hex.EncodeToString(certificateFingerprint[:]), Certificate: certificate}, nil
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
	pollCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		document, certErr := request.Client.EndpointCertificate(pollCtx, request.CLIClientSessionID, 1)
		if certErr == nil {
			current := time.Now().UTC()
			if request.Now != nil {
				current = request.Now().UTC()
			}
			current = current.Truncate(time.Second)
			remoteRoot, rootErr := request.Client.E2EERoot(pollCtx)
			if rootErr != nil {
				return Result{}, rootErr
			}
			remoteTrusted, err := validateRemoteRoot(remoteRoot)
			if err != nil || !equalTrustedKeys(trusted, remoteTrusted) {
				trustedkeys.Clear(remoteTrusted)
				return Result{}, ErrInvalid
			}
			trustedkeys.Clear(remoteTrusted)
			verified, err := verifyEnrolledCLI(document, trusted, request.AccountID, request.CLIClientSessionID, keys, current)
			if err != nil {
				return Result{}, err
			}
			if !ok {
				localKey, ok = endpointidentity.TrustedKeyFor(trusted, verified.keyID)
			}
			if !ok {
				clear(verified.raw)
				return Result{}, ErrInvalid
			}
			if err := request.Store.SavePeerAccountRootPublic(request.Issuer, request.AccountID, localKey.PublicKey); err != nil {
				return Result{}, err
			}
			if _, err := request.Store.SavePeerCertificate(request.Issuer, request.CLIClientSessionID, verified.raw); err != nil {
				clear(verified.raw)
				return Result{}, err
			}
			clear(verified.raw)
			return Result{RootFingerprint: verified.keyFingerprint, CertificateFingerprint: verified.certificateFingerprint, Certificate: verified.certificate}, nil
		}
		if !api.IsNotFound(certErr) {
			return Result{}, certErr
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

type verifiedEnrollment struct {
	certificate            endpointidentity.Certificate
	raw                    []byte
	keyID                  string
	keyFingerprint         string
	certificateFingerprint string
}

func validateRemoteRoot(root api.E2EERoot) ([]endpointidentity.TrustedKey, error) {
	keys, err := trustedkeys.Root(root)
	if err != nil {
		return nil, ErrInvalid
	}
	return keys, nil
}

func equalTrustedKeys(left, right []endpointidentity.TrustedKey) bool {
	if len(left) != len(right) {
		return false
	}
	for _, key := range left {
		other, ok := endpointidentity.TrustedKeyFor(right, key.KeyID)
		if !ok || key.Generation != other.Generation || key.Fingerprint != other.Fingerprint || !bytes.Equal(key.PublicKey, other.PublicKey) {
			return false
		}
	}
	return true
}

func validatePendingCLIEnrollment(pending api.PendingEndpointIdentity, endpointID string, noise [32]byte, quic ed25519.PublicKey, now time.Time) error {
	if !boundedID(pending.RequestID) || pending.EndpointID != endpointID || pending.Role != "cli" || (pending.State != "pending" && pending.State != "fulfilled") || pending.Generation != 1 || pending.CreatedAt.After(now.Add(time.Minute)) {
		return ErrInvalid
	}
	// A fulfilled enrollment is deliberately replayable with the same bound
	// operation and public keys, even after its approval window has elapsed:
	// the caller must be able to recover an already-issued certificate after a
	// local persistence failure. A pending request still has a strict expiry.
	if pending.State == "pending" && !pending.ExpiresAt.After(now) {
		return ErrInvalid
	}
	expectedNoise := base64.RawURLEncoding.EncodeToString(noise[:])
	expectedQUIC := base64.RawURLEncoding.EncodeToString(quic)
	if pending.NoisePublicKey != expectedNoise || pending.QUICPublicKey != expectedQUIC || pending.NoisePublicKey == "" || pending.QUICPublicKey == "" {
		return ErrInvalid
	}
	return nil
}

func verifyEnrolledCLI(document api.EndpointCertificateDocument, trusted []endpointidentity.TrustedKey, accountID, endpointID string, keys config.PeerIdentityKeys, now time.Time) (verifiedEnrollment, error) {
	key, ok := endpointidentity.TrustedKeyFor(trusted, document.KeyID)
	if !ok {
		return verifiedEnrollment{}, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(document.Certificate)
	certificateFingerprint := sha256.Sum256(raw)
	quicPublic, ok := keys.QUICPrivate.Public().(ed25519.PublicKey)
	if !ok {
		clear(raw)
		return verifiedEnrollment{}, ErrInvalid
	}
	certificate, verifyErr := endpointidentity.Verify(raw, key.PublicKey, endpointidentity.Expected{AccountID: accountID, Role: endpointidentity.RoleCLI, EndpointID: endpointID, Generation: 1}, now)
	if err != nil || len(raw) == 0 || base64.RawURLEncoding.EncodeToString(raw) != document.Certificate || verifyErr != nil || document.Version != 1 || document.AccountID != accountID || document.KeyID != key.KeyID || document.EndpointID != endpointID || document.Role != "cli" || document.Generation != 1 || document.Serial != certificate.Claims.Serial || document.IssuedAt != certificate.Claims.IssuedAt.Format(time.RFC3339) || document.ExpiresAt != certificate.Claims.ExpiresAt.Format(time.RFC3339) || document.CertificateFingerprint != hex.EncodeToString(certificateFingerprint[:]) || certificate.Claims.NoisePublicKey != keys.NoisePublic || !bytes.Equal(certificate.Claims.QUICPublicKey, quicPublic) {
		clear(raw)
		return verifiedEnrollment{}, ErrInvalid
	}
	return verifiedEnrollment{certificate: certificate, raw: raw, keyID: key.KeyID, keyFingerprint: trustedkeys.FingerprintString(key), certificateFingerprint: document.CertificateFingerprint}, nil
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
		return Result{}, invalidResponseError{Stage: "request"}
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
	if request.AllowRootReplacement {
		keys, err = request.Store.FreshPeerIdentityKeys(request.Issuer, request.AccountID, request.CLIClientSessionID)
	} else if rootExists {
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
		return Result{}, invalidResponseError{Stage: "local_signing_key"}
	}
	keyFingerprint := sha256.Sum256(rootPublic)
	keyID := "aek_" + hex.EncodeToString(keyFingerprint[:])
	if rootExists && !request.AllowRootReplacement {
		trusted, trustedErr := validateRemoteRoot(remoteRoot)
		if trustedErr != nil {
			return Result{}, ErrInvalid
		}
		_, trustedOK := trustedkeys.ByPublic(trusted, rootPublic)
		trustedkeys.Clear(trusted)
		if !trustedOK {
			return Result{}, ErrInvalid
		}
	}
	certificate, raw, err := loadOrCreateCertificate(request, keys, rootPublic, now)
	if err != nil {
		var detailed invalidResponseError
		if errors.As(err, &detailed) {
			return Result{}, err
		}
		if errors.Is(err, ErrInvalid) {
			return Result{}, invalidResponseError{Stage: "local_certificate"}
		}
		return Result{}, err
	}
	certificateFingerprint := sha256.Sum256(raw)
	operationID := "op_peer_bootstrap_" + hex.EncodeToString(certificateFingerprint[:16])
	document := api.EndpointCertificateDocument{Version: 1, AccountID: request.AccountID, KeyID: keyID, EndpointID: request.CLIClientSessionID, Role: "cli", Generation: certificate.Claims.Generation, Serial: certificate.Claims.Serial, IssuedAt: certificate.Claims.IssuedAt.Format(time.RFC3339), ExpiresAt: certificate.Claims.ExpiresAt.Format(time.RFC3339), Certificate: base64.RawURLEncoding.EncodeToString(raw), CertificateFingerprint: hex.EncodeToString(certificateFingerprint[:])}
	input := api.E2EEBootstrapInput{RootPublicKey: base64.RawURLEncoding.EncodeToString(rootPublic), Certificate: document}
	var response api.E2EEBootstrapResult
	if request.AllowRootReplacement {
		fresh, ok := request.Client.(FreshClient)
		if ok {
			response, err = fresh.BootstrapE2EEFresh(ctx, operationID, input)
		} else {
			// A client that has no explicit fresh endpoint can still perform the
			// initial bootstrap when the server has no root yet.
			response, err = request.Client.BootstrapE2EE(ctx, operationID, input)
		}
	} else {
		response, err = request.Client.BootstrapE2EE(ctx, operationID, input)
	}
	if err != nil {
		return Result{}, err
	}
	trusted, trustedErr := trustedkeys.Bootstrap(response)
	if trustedErr != nil && len(response.TrustedKeys) == 0 && response.KeyID == keyID {
		trusted = []endpointidentity.TrustedKey{{KeyID: keyID, PublicKey: append(ed25519.PublicKey(nil), rootPublic...), Fingerprint: keyFingerprint, Generation: 1}}
		trustedErr = nil
	}
	if trustedErr != nil {
		return Result{}, invalidResponseError{Stage: "trusted_keys"}
	}
	if response.KeyID != keyID {
		return Result{}, invalidResponseError{Stage: "key_id"}
	}
	if !sameEndpointCertificateDocument(response.Certificate, document) {
		return Result{}, invalidResponseError{Stage: "certificate_document"}
	}
	defer trustedkeys.Clear(trusted)
	if _, ok := trustedkeys.ByPublic(trusted, rootPublic); !ok {
		return Result{}, invalidResponseError{Stage: "new_key_missing"}
	}
	if _, err := verifyEnrolledCLI(response.Certificate, trusted, request.AccountID, request.CLIClientSessionID, keys, now); err != nil {
		if errors.Is(err, ErrInvalid) {
			return Result{}, invalidResponseError{Stage: "certificate_verification"}
		}
		return Result{}, err
	}
	if err := request.Store.SavePeerAccountRootPublic(request.Issuer, request.AccountID, rootPublic); err != nil {
		return Result{}, err
	}
	if _, err := request.Store.SavePeerCertificate(request.Issuer, request.CLIClientSessionID, raw); err != nil {
		return Result{}, err
	}
	return Result{RootFingerprint: hex.EncodeToString(keyFingerprint[:]), CertificateFingerprint: document.CertificateFingerprint, Certificate: certificate}, nil
}

// Compare the canonical wire fields explicitly. Struct equality is unsuitable
// here because EndpointCertificateDocument also carries compatibility-only
// fields that are intentionally omitted by the v1 server response.
func sameEndpointCertificateDocument(left, right api.EndpointCertificateDocument) bool {
	return left.Version == right.Version && left.AccountID == right.AccountID &&
		left.KeyID == right.KeyID && left.EndpointID == right.EndpointID &&
		left.Role == right.Role && left.Generation == right.Generation &&
		left.Serial == right.Serial && left.IssuedAt == right.IssuedAt &&
		left.ExpiresAt == right.ExpiresAt && left.Certificate == right.Certificate &&
		left.CertificateFingerprint == right.CertificateFingerprint
}

func loadOrCreateCertificate(request Request, keys config.PeerIdentityKeys, rootPublic ed25519.PublicKey, now time.Time) (endpointidentity.Certificate, []byte, error) {
	state, err := request.Store.LoadPeerCertificate(request.Issuer, request.CLIClientSessionID)
	if err == nil {
		certificate, verifyErr := endpointidentity.Verify(state.Raw, rootPublic, endpointidentity.Expected{AccountID: request.AccountID, Role: endpointidentity.RoleCLI, EndpointID: request.CLIClientSessionID, Generation: 1}, now)
		if verifyErr != nil {
			if request.AllowRootReplacement {
				clear(state.Raw)
				if err := request.Store.DeletePeerCertificate(request.Issuer, request.CLIClientSessionID); err != nil {
					return endpointidentity.Certificate{}, nil, err
				}
				return createPeerCertificate(request, keys, rootPublic, now)
			}
			clear(state.Raw)
			return endpointidentity.Certificate{}, nil, invalidResponseError{Stage: "local_certificate_signature"}
		}
		if certificate.Claims.NoisePublicKey != keys.NoisePublic {
			clear(state.Raw)
			return endpointidentity.Certificate{}, nil, invalidResponseError{Stage: "local_certificate_noise_key"}
		}
		if !bytes.Equal(certificate.Claims.QUICPublicKey, keys.QUICPrivate.Public().(ed25519.PublicKey)) {
			clear(state.Raw)
			return endpointidentity.Certificate{}, nil, invalidResponseError{Stage: "local_certificate_quic_key"}
		}
		return certificate, state.Raw, nil
	}
	if !errors.Is(err, config.ErrSecretNotFound) {
		return endpointidentity.Certificate{}, nil, err
	}
	return createPeerCertificate(request, keys, rootPublic, now)
}

func createPeerCertificate(request Request, keys config.PeerIdentityKeys, rootPublic ed25519.PublicKey, now time.Time) (endpointidentity.Certificate, []byte, error) {
	quicPublic := keys.QUICPrivate.Public().(ed25519.PublicKey)
	certificate, err := endpointidentity.Sign(keys.RootPrivate, endpointidentity.Claims{AccountID: request.AccountID, Role: endpointidentity.RoleCLI, EndpointID: request.CLIClientSessionID, NoisePublicKey: keys.NoisePublic, QUICPublicKey: quicPublic, Generation: 1, Serial: 1, IssuedAt: now.Add(-CertificateClockSkew), ExpiresAt: now.Add(CertificateLifetime)})
	if err != nil {
		return endpointidentity.Certificate{}, nil, err
	}
	raw, err := certificate.MarshalBinary()
	if err != nil {
		return endpointidentity.Certificate{}, nil, err
	}
	state, err := request.Store.SavePeerCertificate(request.Issuer, request.CLIClientSessionID, raw)
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
