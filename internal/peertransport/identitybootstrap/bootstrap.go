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

type Client interface {
	E2EERoot(context.Context) (api.E2EERoot, error)
	BootstrapE2EE(context.Context, string, api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error)
}

// ExistingRootClient is the small control-plane surface needed to enroll a
// new CLI endpoint without ever possessing the account root private key.
type ExistingRootClient interface {
	E2EERoot(context.Context) (api.E2EERoot, error)
	RequestCLIEndpoint(context.Context, api.CLIEndpointRequestInput) (api.PendingEndpointIdentity, error)
	EndpointCertificate(context.Context, string, uint64) (api.EndpointCertificateDocument, error)
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
	if !boundedID(pending.RequestID) || pending.EndpointID != endpointID || pending.Role != "cli" || pending.Generation != 1 || !pending.ExpiresAt.After(now) || pending.CreatedAt.After(now.Add(time.Minute)) {
		return ErrInvalid
	}
	expectedNoise := base64.RawURLEncoding.EncodeToString(noise[:])
	expectedQUIC := base64.RawURLEncoding.EncodeToString(quic)
	if pending.NoisePublicKey != expectedNoise || pending.QUICPublicKey != expectedQUIC || pending.NoisePublicKey == "" || pending.QUICPublicKey == "" {
		return ErrInvalid
	}
	return nil
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
