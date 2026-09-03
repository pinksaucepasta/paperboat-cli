package identitybootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/trustedkeys"
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
	return approveEndpoint(ctx, request, endpointidentity.RoleMachine)
}

// ApproveCLI signs a pending CLI endpoint request with the existing account
// root. The caller must be an already paired CLI daemon for that same account.
func ApproveCLI(ctx context.Context, request ApprovalRequest) (Result, error) {
	return approveEndpoint(ctx, request, endpointidentity.RoleCLI)
}

func approveEndpoint(ctx context.Context, request ApprovalRequest, wantRole endpointidentity.Role) (Result, error) {
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
	rootKeys, rootErr := trustedkeys.Root(root)
	if rootErr != nil {
		return Result{}, ErrInvalid
	}
	defer trustedkeys.Clear(rootKeys)
	rootPublic, ok := keys.RootPrivate.Public().(ed25519.PublicKey)
	if !ok {
		return Result{}, ErrInvalid
	}
	trustedRoot, ok := trustedkeys.ByPublic(rootKeys, rootPublic)
	if !ok {
		return Result{}, ErrInvalid
	}
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
	if selected == nil || selected.State != "pending" || selected.SafetyCode != request.SafetyCode || !selected.ExpiresAt.After(now) || selected.CreatedAt.After(now.Add(time.Minute)) || selected.Generation == 0 || !boundedID(selected.EndpointID) {
		return Result{}, ErrInvalid
	}
	selectedRole := endpointidentity.RoleMachine
	if selected.Role == "cli" {
		selectedRole = endpointidentity.RoleCLI
	} else if selected.Role != "" && selected.Role != "machine" {
		return Result{}, ErrInvalid
	}
	if selectedRole != wantRole {
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
	// Approval is performed by a paired endpoint, while the newly approved
	// endpoint and the control plane may have slightly different wall clocks.
	// Keep the certificate valid at the control plane when the signer is ahead,
	// using the same bounded skew as fresh bootstrap issuance.
	issuedAt := now.Add(-CertificateClockSkew)
	expiresAt := now.Add(CertificateLifetime)
	certificate, err := endpointidentity.Sign(keys.RootPrivate, endpointidentity.Claims{AccountID: request.AccountID, Role: wantRole, EndpointID: selected.EndpointID, NoisePublicKey: noisePublic, QUICPublicKey: ed25519.PublicKey(quic), Generation: selected.Generation, Serial: 1, IssuedAt: issuedAt, ExpiresAt: expiresAt})
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
	roleName, operationPrefix := "machine", "op_peer_machine_cert_"
	if wantRole == endpointidentity.RoleCLI {
		roleName, operationPrefix = "cli", "op_peer_cli_cert_"
	}
	operationID := operationPrefix + hex.EncodeToString(fingerprint[:16])
	document := api.EndpointCertificateDocument{Version: 1, AccountID: request.AccountID, KeyID: trustedRoot.KeyID, EndpointID: selected.EndpointID, Role: roleName, Generation: selected.Generation, Serial: 1, IssuedAt: issuedAt.Format(time.RFC3339), ExpiresAt: expiresAt.Format(time.RFC3339), Certificate: base64.RawURLEncoding.EncodeToString(raw), CertificateFingerprint: hex.EncodeToString(fingerprint[:])}
	response, err := request.Client.RegisterEndpointCertificate(ctx, operationID, document)
	if err != nil {
		return Result{}, err
	}
	if response != document {
		return Result{}, ErrInvalid
	}
	return Result{RootFingerprint: trustedkeys.FingerprintString(trustedRoot), CertificateFingerprint: document.CertificateFingerprint, Certificate: certificate}, nil
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
