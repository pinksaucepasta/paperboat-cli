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

type Client interface {
	E2EERoot(context.Context) (api.E2EERoot, error)
	BootstrapE2EE(context.Context, string, api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error)
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
