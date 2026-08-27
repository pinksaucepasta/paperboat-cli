package hostruntimecmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/localdaemon"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/identitybootstrap"
)

type bootstrapCLIClient interface {
	Me(context.Context) (api.Me, error)
	E2EERoot(context.Context) (api.E2EERoot, error)
	BootstrapE2EE(context.Context, string, api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error)
	RequestCLIEndpoint(context.Context, api.CLIEndpointRequestInput) (api.PendingEndpointIdentity, error)
	EndpointCertificate(context.Context, string, uint64) (api.EndpointCertificateDocument, error)
}

type bootstrapCLIIdentityInstaller func(context.Context, config.ProfileStore, bootstrapCLIClient, string, api.Me, string) error

// installBootstrapCLI completes the user side of a Client enrollment. Host
// installs must not replace the account CLI E2EE root, because doing so would
// revoke an already enrolled client and break its SSH authority.
func installBootstrapCLI(ctx context.Context, session *bootstrap.ClientSession, serverURL string) error {
	if session == nil || session.Schema != "paperboat.cli-session/v1" || session.SessionID == "" || session.AccessToken == "" || session.RefreshToken == "" || session.ExpiresIn <= 0 {
		return errors.New("server returned invalid CLI session")
	}
	cfg, err := config.Load("")
	if err != nil {
		return err
	}
	cfg.ServerURL = strings.TrimRight(serverURL, "/")
	store, err := config.ProfileStoreFor(cfg)
	if err != nil {
		return err
	}
	cred := config.Credential{AccessToken: session.AccessToken, RefreshToken: session.RefreshToken, TokenType: session.TokenType, ExpiresAt: time.Now().UTC().Add(time.Duration(session.ExpiresIn) * time.Second)}
	client := api.New(cfg.ServerURL, cred, nil)
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	return installBootstrapCLIWith(ctx, session, cfg.ServerURL, store, cred, client, enrollBootstrapCLIIdentity, func(ctx context.Context) error {
		return localdaemon.InstallCurrentUserService(ctx, executable, cfg.Path(), cfg.ServerURL)
	})
}

func installBootstrapCLIWith(ctx context.Context, session *bootstrap.ClientSession, issuer string, store config.ProfileStore, cred config.Credential, client bootstrapCLIClient, enroll bootstrapCLIIdentityInstaller, installDaemon func(context.Context) error) error {
	if session == nil || client == nil || enroll == nil || installDaemon == nil {
		return errors.New("bootstrap CLI installation is not configured")
	}
	issuer = strings.TrimRight(issuer, "/")
	me, err := client.Me(ctx)
	if err != nil {
		return fmt.Errorf("validate CLI session: %w", err)
	}
	if strings.TrimSpace(me.ID) == "" {
		return errors.New("server returned an invalid CLI account")
	}
	profile := config.Profile{Issuer: issuer, Account: config.Account{ID: me.ID, Email: me.Email, DisplayName: me.DisplayName}, CLIClientSessionID: session.SessionID, AccessExpiresAt: cred.ExpiresAt}
	if err := store.Recover(issuer); err != nil {
		return fmt.Errorf("recover interrupted CLI profile installation: %w", err)
	}
	if err := saveBootstrapCLIProfile(store, profile, cred); err != nil {
		return err
	}
	if err := enroll(ctx, store, client, issuer, me, session.SessionID); err != nil {
		return err
	}
	return installDaemon(ctx)
}

// saveBootstrapCLIProfile permits a Client bootstrap to replace an older local
// CLI session only when the validated server account matches the profile's
// immutable account ID. Switch keeps the previous refresh token in the durable
// revocation queue before committing the new session, and supports retrying a
// partially completed bootstrap for that same session.
func saveBootstrapCLIProfile(store config.ProfileStore, profile config.Profile, cred config.Credential) error {
	for attempt := 0; attempt < 2; attempt++ {
		existing, err := store.Load(profile.Issuer)
		if errors.Is(err, config.ErrNoCredentials) {
			if err := reconcileBootstrapProfileMutation(store, profile, cred, store.Save(profile, cred)); errors.Is(err, config.ErrProfileExists) && attempt == 0 {
				continue
			} else if err != nil {
				return err
			}
			return nil
		}
		if err != nil {
			return err
		}
		if existing.Account.ID == "" || existing.Account.ID != profile.Account.ID {
			return errors.New("existing Paperboat profile belongs to another account")
		}
		if err := reconcileBootstrapProfileMutation(store, profile, cred, store.Switch(existing.CLIClientSessionID, profile, cred)); errors.Is(err, config.ErrProfileChanged) && attempt == 0 {
			continue
		} else if err != nil {
			return err
		}
		return nil
	}
	return errors.New("Paperboat profile changed while completing bootstrap")
}

func reconcileBootstrapProfileMutation(store config.ProfileStore, profile config.Profile, credential config.Credential, mutationErr error) error {
	if mutationErr == nil {
		return nil
	}
	active, err := store.Load(profile.Issuer)
	if err != nil || active.CLIClientSessionID != profile.CLIClientSessionID {
		return mutationErr
	}
	activeCredential, err := store.CredentialFor(profile.Issuer)
	if err != nil || activeCredential.AccessToken != credential.AccessToken || activeCredential.RefreshToken != credential.RefreshToken {
		return mutationErr
	}
	return nil
}

func enrollBootstrapCLIIdentity(ctx context.Context, store config.ProfileStore, client bootstrapCLIClient, issuer string, me api.Me, sessionID string) error {
	if _, err := identitybootstrap.EnrollCLI(ctx, identitybootstrap.CLIRequest{Store: store, Client: client, Issuer: issuer, AccountID: me.ID, CLIClientSessionID: sessionID, Fresh: true}); err != nil {
		return fmt.Errorf("enroll CLI peer identity: %w", err)
	}
	return nil
}

func shouldInstallBootstrapCLI(material bootstrap.Material) bool {
	return material.ClientSession != nil && material.SetupMode == "client"
}
