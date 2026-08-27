package clientauthority

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

var ErrInvalid = errors.New("peer client authority is invalid")

type CertificateClient interface {
	EndpointCertificate(context.Context, string, uint64) (api.EndpointCertificateDocument, error)
}

type trustedRootReader interface {
	E2EERoot(context.Context) (api.E2EERoot, error)
}

type Request struct {
	Store              config.ProfileStore
	Client             CertificateClient
	Issuer             string
	AccountID          string
	CLIClientSessionID string
	MachineID          string
	MachineGeneration  uint64
	Now                time.Time
}

type Authority struct {
	// RootPublic is the local endpoint's signing key. It is retained only for
	// constructing this endpoint's QUIC leaf; peer certificates are verified
	// against TrustedKeys and never against this single key.
	RootPublic              ed25519.PublicKey
	TrustedKeys             []endpointidentity.TrustedKey
	LocalKeys               config.PeerIdentityKeys
	LocalCertificate        endpointidentity.Certificate
	LocalCertificateRaw     []byte
	MachineCertificate      endpointidentity.Certificate
	MachineCertificateKeyID string
	MachineCertificateRaw   []byte
}

func Resolve(ctx context.Context, request Request) (Authority, error) {
	if ctx == nil || request.Client == nil || request.AccountID == "" || request.CLIClientSessionID == "" || request.MachineID == "" || request.MachineGeneration == 0 || request.Now.IsZero() {
		return Authority{}, ErrInvalid
	}
	var keys config.PeerIdentityKeys
	var trusted []endpointidentity.TrustedKey
	var rootPublic ed25519.PublicKey
	var err error
	fail := func(err error) (Authority, error) {
		trustedkeys.Clear(trusted)
		clear(rootPublic)
		clear(keys.RootPrivate)
		clear(keys.NoisePrivate[:])
		clear(keys.NoisePublic[:])
		clear(keys.QUICPrivate)
		return Authority{}, err
	}
	if reader, ok := request.Client.(trustedRootReader); ok {
		root, rootErr := reader.E2EERoot(ctx)
		if rootErr != nil {
			return fail(rootErr)
		}
		trusted, err = trustedkeys.Root(root)
		if err != nil {
			return fail(ErrInvalid)
		}
	}
	rootPublic, rootErr := request.Store.LoadPeerAccountRootPublic(request.Issuer, request.AccountID)
	if errors.Is(rootErr, config.ErrSecretNotFound) {
		// Profiles created before verifier-only root custody was introduced keep
		// the root seed. Preserve compatibility while ensuring the resolved
		// authority never needs to retain that private key.
		legacy, legacyErr := request.Store.PeerIdentityKeysForExistingRoot(request.Issuer, request.AccountID, request.CLIClientSessionID)
		if legacyErr != nil {
			return fail(legacyErr)
		}
		keys = legacy
		legacyPublic, publicOK := keys.RootPrivate.Public().(ed25519.PublicKey)
		if !publicOK {
			return fail(ErrInvalid)
		}
		rootPublic = append(ed25519.PublicKey(nil), legacyPublic...)
	} else if rootErr != nil {
		return fail(rootErr)
	} else {
		keys, err = request.Store.PeerEndpointKeys(request.Issuer, request.AccountID, request.CLIClientSessionID)
		if err != nil {
			clear(rootPublic)
			return fail(err)
		}
	}
	if len(rootPublic) != ed25519.PublicKeySize {
		return fail(ErrInvalid)
	}
	if len(trusted) == 0 {
		fingerprint := sha256.Sum256(rootPublic)
		trusted = []endpointidentity.TrustedKey{{KeyID: "aek_" + hex.EncodeToString(fingerprint[:]), PublicKey: append(ed25519.PublicKey(nil), rootPublic...), Fingerprint: fingerprint, Generation: 1}}
	}
	localKey, ok := trustedkeys.ByPublic(trusted, rootPublic)
	if !ok {
		return fail(ErrInvalid)
	}
	localState, err := request.Store.LoadPeerCertificate(request.Issuer, request.CLIClientSessionID)
	if err != nil {
		return fail(err)
	}
	local, err := endpointidentity.Verify(localState.Raw, localKey.PublicKey, endpointidentity.Expected{AccountID: request.AccountID, Role: endpointidentity.RoleCLI, EndpointID: request.CLIClientSessionID, Generation: 1}, request.Now.UTC())
	if err != nil || !bytes.Equal(local.Claims.NoisePublicKey[:], keys.NoisePublic[:]) || !bytes.Equal(local.Claims.QUICPublicKey, keys.QUICPrivate.Public().(ed25519.PublicKey)) {
		clear(localState.Raw)
		return fail(ErrInvalid)
	}
	document, err := request.Client.EndpointCertificate(ctx, request.MachineID, request.MachineGeneration)
	if err != nil {
		clear(localState.Raw)
		return fail(err)
	}
	machineKey, ok := endpointidentity.TrustedKeyFor(trusted, document.KeyID)
	if !ok && document.KeyID == "" && len(trusted) == 1 {
		// Internal fixture adapter. Server-issued documents always carry key_id.
		machineKey, ok = trusted[0], true
	}
	if !ok {
		clear(localState.Raw)
		return fail(ErrInvalid)
	}
	machineRaw, decodeErr := base64.RawURLEncoding.Strict().DecodeString(document.Certificate)
	machineFingerprint := sha256.Sum256(machineRaw)
	machine, verifyErr := endpointidentity.Verify(machineRaw, machineKey.PublicKey, endpointidentity.Expected{AccountID: request.AccountID, Role: endpointidentity.RoleMachine, EndpointID: request.MachineID, Generation: request.MachineGeneration}, request.Now.UTC())
	if decodeErr != nil || base64.RawURLEncoding.EncodeToString(machineRaw) != document.Certificate || verifyErr != nil || document.Version != 1 || document.AccountID != request.AccountID || document.KeyID != "" && document.KeyID != machineKey.KeyID || document.EndpointID != request.MachineID || document.Role != "machine" || document.Generation != request.MachineGeneration || document.Serial != machine.Claims.Serial || document.IssuedAt != machine.Claims.IssuedAt.Format(time.RFC3339) || document.ExpiresAt != machine.Claims.ExpiresAt.Format(time.RFC3339) || document.CertificateFingerprint != hex.EncodeToString(machineFingerprint[:]) {
		clear(localState.Raw)
		clear(machineRaw)
		return fail(ErrInvalid)
	}
	localRootPublic := append(ed25519.PublicKey(nil), localKey.PublicKey...)
	clear(rootPublic)
	return Authority{RootPublic: localRootPublic, TrustedKeys: trusted, LocalKeys: keys, LocalCertificate: local, LocalCertificateRaw: localState.Raw, MachineCertificate: machine, MachineCertificateKeyID: machineKey.KeyID, MachineCertificateRaw: machineRaw}, nil
}

func (a *Authority) Clear() {
	if a == nil {
		return
	}
	trustedkeys.Clear(a.TrustedKeys)
	clear(a.RootPublic)
	clear(a.LocalKeys.RootPrivate)
	clear(a.LocalKeys.NoisePrivate[:])
	clear(a.LocalKeys.NoisePublic[:])
	clear(a.LocalKeys.QUICPrivate)
	clear(a.LocalCertificateRaw)
	clear(a.MachineCertificateRaw)
	*a = Authority{}
}
