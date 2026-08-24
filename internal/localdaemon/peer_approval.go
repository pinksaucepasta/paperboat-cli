package localdaemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/identitybootstrap"
)

var ErrPeerApprovalSignerUnavailable = errors.New("peer enrollment signer is unavailable")

// PeerApprovalSignerUnavailableError is a non-fatal local capability result:
// this authenticated profile can verify the account root, but it does not
// possess the root seed required to sign pending endpoint certificates.
type PeerApprovalSignerUnavailableError struct {
	PendingRequests int
}

func (e *PeerApprovalSignerUnavailableError) Error() string {
	return fmt.Sprintf("%v for %d pending request(s)", ErrPeerApprovalSignerUnavailable, e.PendingRequests)
}

func (e *PeerApprovalSignerUnavailableError) Unwrap() error {
	return ErrPeerApprovalSignerUnavailable
}

// ApproveOwnedPeerEnrollments completes the authenticated one-shot enrollment
// handshake. The pending request is eligible only when its endpoint ID is
// already present in the account-scoped machine list. The exact server-issued
// safety code is then passed to the existing root-key signer, so the daemon
// cannot approve an endpoint outside this account or fabricate trust data.
func ApproveOwnedPeerEnrollments(ctx context.Context, store config.ProfileStore, profile config.Profile, client *api.Client, machines []api.UserMachine) error {
	if client == nil || profile.Account.ID == "" || profile.CLIClientSessionID == "" || profile.Issuer == "" {
		return errors.New("automatic peer enrollment approval is not configured")
	}
	owned := make(map[string]struct{}, len(machines))
	for _, machine := range machines {
		if machine.ID != "" && machine.State != "revoked" && machine.State != "deleted" {
			owned[machine.ID] = struct{}{}
		}
	}
	pending, err := client.PendingE2EEEndpoints(ctx)
	if err != nil {
		return err
	}
	eligible := make([]api.PendingEndpointIdentity, 0, len(pending))
	for _, request := range pending {
		if request.Role == "cli" {
			eligible = append(eligible, request)
			continue
		}
		if request.Role != "" && request.Role != "machine" {
			return errors.New("automatic peer enrollment returned an invalid endpoint role")
		}
		if _, ok := owned[request.EndpointID]; !ok {
			continue
		}
		eligible = append(eligible, request)
	}
	if len(eligible) == 0 {
		return nil
	}
	seed, err := store.ExportPeerAccountRootSeed(profile.Issuer, profile.Account.ID)
	if errors.Is(err, config.ErrSecretNotFound) {
		if err := validateVerifierOnlyRoot(ctx, store, profile, client); err != nil {
			return err
		}
		return &PeerApprovalSignerUnavailableError{PendingRequests: len(eligible)}
	}
	if err != nil {
		return err
	}
	clear(seed)
	for _, request := range eligible {
		approval := identitybootstrap.ApprovalRequest{
			Store: store, Client: client, Issuer: profile.Issuer, AccountID: profile.Account.ID,
			CLIClientSessionID: profile.CLIClientSessionID, RequestID: request.RequestID, SafetyCode: request.SafetyCode,
		}
		if request.Role == "cli" {
			_, err = identitybootstrap.ApproveCLI(ctx, approval)
		} else {
			_, err = identitybootstrap.ApproveMachine(ctx, approval)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func validateVerifierOnlyRoot(ctx context.Context, store config.ProfileStore, profile config.Profile, client *api.Client) error {
	local, err := store.LoadPeerAccountRootPublic(profile.Issuer, profile.Account.ID)
	if err != nil {
		return err
	}
	defer clear(local)
	remote, err := client.E2EERoot(ctx)
	if err != nil {
		return err
	}
	decoded, decodeErr := base64.RawURLEncoding.Strict().DecodeString(remote.PublicKey)
	defer clear(decoded)
	fingerprint := sha256.Sum256(decoded)
	if decodeErr != nil || len(local) != ed25519.PublicKeySize || len(decoded) != ed25519.PublicKeySize ||
		base64.RawURLEncoding.EncodeToString(decoded) != remote.PublicKey || remote.Version != 1 || remote.Generation != 1 ||
		remote.Fingerprint != hex.EncodeToString(fingerprint[:]) || !bytes.Equal(local, decoded) {
		return errors.New("automatic peer enrollment verifier root does not match the account root")
	}
	return nil
}
