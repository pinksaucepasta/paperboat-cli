package identitybootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

type ApprovalClient interface {
	E2EERoot(context.Context) (api.E2EERoot, error)
	PendingE2EEEndpoints(context.Context) ([]api.PendingEndpointIdentity, error)
	RegisterEndpointCertificate(context.Context, string, api.EndpointCertificateDocument) (api.EndpointCertificateDocument, error)
}

type ApprovalRequest struct {
	Store              config.ProfileStore
	Client             ApprovalClient
	Issuer             string
	AccountID          string
	CLIClientSessionID string
	RequestID          string
	SafetyCode         string
	Now                func() time.Time
}

func ApproveMachine(ctx context.Context, request ApprovalRequest) (Result, error) {
	if ctx == nil || request.Client == nil || !boundedID(request.AccountID) || !boundedID(request.CLIClientSessionID) || !boundedID(request.RequestID) || len(request.SafetyCode) != 11 || request.SafetyCode[5] != '-' {
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
	keys, err := request.Store.PeerIdentityKeysForExistingRoot(request.Issuer, request.AccountID, request.CLIClientSessionID)
	if err != nil {
		return Result{}, err
	}
	defer clearKeys(&keys)
	rootPublic := keys.RootPrivate.Public().(ed25519.PublicKey)
	rootFingerprint := sha256.Sum256(rootPublic)
	decodedRoot, decodeErr := base64.RawURLEncoding.Strict().DecodeString(root.PublicKey)
	if decodeErr != nil || root.Version != 1 || root.Generation != 1 || root.Fingerprint != hex.EncodeToString(rootFingerprint[:]) || !bytes.Equal(decodedRoot, rootPublic) {
		clear(decodedRoot)
		return Result{}, ErrInvalid
	}
	clear(decodedRoot)
	pending, err := request.Client.PendingE2EEEndpoints(ctx)
	if err != nil {
		return Result{}, err
	}
	var selected *api.PendingEndpointIdentity
	for index := range pending {
		if pending[index].RequestID == request.RequestID {
			if selected != nil {
				return Result{}, ErrInvalid
			}
			selected = &pending[index]
		}
	}
	if selected == nil || selected.SafetyCode != request.SafetyCode || !selected.ExpiresAt.After(now) || selected.CreatedAt.After(now.Add(time.Minute)) || selected.Generation == 0 || !boundedID(selected.EndpointID) {
		return Result{}, ErrInvalid
	}
	noise, noiseErr := base64.RawURLEncoding.Strict().DecodeString(selected.NoisePublicKey)
	quic, quicErr := base64.RawURLEncoding.Strict().DecodeString(selected.QUICPublicKey)
	if noiseErr != nil || quicErr != nil || len(noise) != 32 || len(quic) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(noise) != selected.NoisePublicKey || base64.RawURLEncoding.EncodeToString(quic) != selected.QUICPublicKey || allZero(noise) || allZero(quic) {
		clear(noise)
		clear(quic)
		return Result{}, ErrInvalid
	}
	var noisePublic [32]byte
	copy(noisePublic[:], noise)
	certificate, err := endpointidentity.Sign(keys.RootPrivate, endpointidentity.Claims{AccountID: request.AccountID, Role: endpointidentity.RoleMachine, EndpointID: selected.EndpointID, NoisePublicKey: noisePublic, QUICPublicKey: ed25519.PublicKey(quic), Generation: selected.Generation, Serial: 1, IssuedAt: now, ExpiresAt: now.Add(CertificateLifetime)})
	clear(noise)
	clear(quic)
	if err != nil {
		return Result{}, err
	}
	raw, err := certificate.MarshalBinary()
	if err != nil {
		return Result{}, err
	}
	fingerprint := sha256.Sum256(raw)
	operationID := "op_peer_machine_cert_" + hex.EncodeToString(fingerprint[:16])
	document := api.EndpointCertificateDocument{Version: 1, AccountID: request.AccountID, RootFingerprint: hex.EncodeToString(rootFingerprint[:]), EndpointID: selected.EndpointID, Role: "machine", Generation: selected.Generation, Serial: 1, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(CertificateLifetime).Format(time.RFC3339), Certificate: base64.RawURLEncoding.EncodeToString(raw), CertificateFingerprint: hex.EncodeToString(fingerprint[:])}
	response, err := request.Client.RegisterEndpointCertificate(ctx, operationID, document)
	if err != nil {
		return Result{}, err
	}
	if response != document {
		return Result{}, ErrInvalid
	}
	return Result{RootFingerprint: document.RootFingerprint, CertificateFingerprint: document.CertificateFingerprint, Certificate: certificate}, nil
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
