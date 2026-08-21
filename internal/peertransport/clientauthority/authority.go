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
)

var ErrInvalid = errors.New("peer client authority is invalid")

type CertificateClient interface {
	EndpointCertificate(context.Context, string, uint64) (api.EndpointCertificateDocument, error)
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
	RootPublic            ed25519.PublicKey
	LocalKeys             config.PeerIdentityKeys
	LocalCertificate      endpointidentity.Certificate
	LocalCertificateRaw   []byte
	MachineCertificate    endpointidentity.Certificate
	MachineCertificateRaw []byte
}

func Resolve(ctx context.Context, request Request) (Authority, error) {
	if ctx == nil || request.Client == nil || request.AccountID == "" || request.CLIClientSessionID == "" || request.MachineID == "" || request.MachineGeneration == 0 || request.Now.IsZero() {
		return Authority{}, ErrInvalid
	}
	var keys config.PeerIdentityKeys
	var err error
	fail := func(err error) (Authority, error) {
		clear(keys.RootPrivate)
		clear(keys.NoisePrivate[:])
		clear(keys.NoisePublic[:])
		clear(keys.QUICPrivate)
		return Authority{}, err
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
		rootPublic = append(ed25519.PublicKey(nil), keys.RootPrivate.Public().(ed25519.PublicKey)...)
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
		clear(rootPublic)
		return fail(ErrInvalid)
	}
	localState, err := request.Store.LoadPeerCertificate(request.Issuer, request.CLIClientSessionID)
	if err != nil {
		return fail(err)
	}
	local, err := endpointidentity.Verify(localState.Raw, rootPublic, endpointidentity.Expected{AccountID: request.AccountID, Role: endpointidentity.RoleCLI, EndpointID: request.CLIClientSessionID, Generation: 1}, request.Now.UTC())
	if err != nil || !bytes.Equal(local.Claims.NoisePublicKey[:], keys.NoisePublic[:]) || !bytes.Equal(local.Claims.QUICPublicKey, keys.QUICPrivate.Public().(ed25519.PublicKey)) {
		clear(localState.Raw)
		return fail(ErrInvalid)
	}
	document, err := request.Client.EndpointCertificate(ctx, request.MachineID, request.MachineGeneration)
	if err != nil {
		clear(localState.Raw)
		return fail(err)
	}
	machineRaw, decodeErr := base64.RawURLEncoding.Strict().DecodeString(document.Certificate)
	machineFingerprint := sha256.Sum256(machineRaw)
	rootFingerprint := sha256.Sum256(rootPublic)
	machine, verifyErr := endpointidentity.Verify(machineRaw, rootPublic, endpointidentity.Expected{AccountID: request.AccountID, Role: endpointidentity.RoleMachine, EndpointID: request.MachineID, Generation: request.MachineGeneration}, request.Now.UTC())
	if decodeErr != nil || base64.RawURLEncoding.EncodeToString(machineRaw) != document.Certificate || verifyErr != nil || document.Version != 1 || document.AccountID != request.AccountID || document.RootFingerprint != hex.EncodeToString(rootFingerprint[:]) || document.EndpointID != request.MachineID || document.Role != "machine" || document.Generation != request.MachineGeneration || document.Serial != machine.Claims.Serial || document.IssuedAt != machine.Claims.IssuedAt.Format(time.RFC3339) || document.ExpiresAt != machine.Claims.ExpiresAt.Format(time.RFC3339) || document.CertificateFingerprint != hex.EncodeToString(machineFingerprint[:]) {
		clear(localState.Raw)
		clear(machineRaw)
		return fail(ErrInvalid)
	}
	return Authority{RootPublic: rootPublic, LocalKeys: keys, LocalCertificate: local, LocalCertificateRaw: localState.Raw, MachineCertificate: machine, MachineCertificateRaw: machineRaw}, nil
}

func (a *Authority) Clear() {
	if a == nil {
		return
	}
	clear(a.RootPublic)
	clear(a.LocalKeys.RootPrivate)
	clear(a.LocalKeys.NoisePrivate[:])
	clear(a.LocalKeys.NoisePublic[:])
	clear(a.LocalKeys.QUICPrivate)
	clear(a.LocalCertificateRaw)
	clear(a.MachineCertificateRaw)
	*a = Authority{}
}
