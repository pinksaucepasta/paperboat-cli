package localdaemon

import (
	"context"
	"errors"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/identitybootstrap"
)

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
	for _, request := range pending {
		if request.Role == "cli" {
			if _, err := identitybootstrap.ApproveCLI(ctx, identitybootstrap.ApprovalRequest{
				Store: store, Client: client, Issuer: profile.Issuer, AccountID: profile.Account.ID,
				CLIClientSessionID: profile.CLIClientSessionID, RequestID: request.RequestID, SafetyCode: request.SafetyCode,
			}); err != nil {
				return err
			}
			continue
		}
		if request.Role != "" && request.Role != "machine" {
			return errors.New("automatic peer enrollment returned an invalid endpoint role")
		}
		if _, ok := owned[request.EndpointID]; !ok {
			continue
		}
		if _, err := identitybootstrap.ApproveMachine(ctx, identitybootstrap.ApprovalRequest{
			Store: store, Client: client, Issuer: profile.Issuer, AccountID: profile.Account.ID,
			CLIClientSessionID: profile.CLIClientSessionID, RequestID: request.RequestID, SafetyCode: request.SafetyCode,
		}); err != nil {
			return err
		}
	}
	return nil
}
