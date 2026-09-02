package hostruntimecmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/identitybootstrap"
)

type bootstrapCLIClient interface {
	Me(context.Context) (api.Me, error)
	E2EERoot(context.Context) (api.E2EERoot, error)
	BootstrapE2EE(context.Context, string, api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error)
	BootstrapE2EEFresh(context.Context, string, api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error)
	RequestCLIEndpoint(context.Context, api.CLIEndpointRequestInput) (api.PendingEndpointIdentity, error)
	EndpointCertificate(context.Context, string, uint64) (api.EndpointCertificateDocument, error)
}

type bootstrapCLIIdentityInstaller func(context.Context, config.ProfileStore, bootstrapCLIClient, string, api.Me, string) error

// installBootstrapCLI completes the user side of an enrollment. Host setup is
// a superset of Client setup, so both modes receive the local CLI profile,
// endpoint identity, and daemon. The host runtime is installed separately by
// the mode-specific bootstrap path.
func installBootstrapCLI(ctx context.Context, session *bootstrap.ClientSession, serverURL string) error {
	if session == nil || session.Schema != "paperboat.cli-session/v1" || session.SessionID == "" || session.AccessToken == "" || session.RefreshToken == "" || session.ExpiresIn <= 0 {
		return errors.New("server returned invalid CLI session")
	}
	cfg, err := config.Load("")
	if err != nil {
		return err
	}
	cfg.ServerURL = strings.TrimRight(serverURL, "/")
	// Dashboard bootstrap is non-interactive. On headless Linux there is no
	// Secret Service session, so select the owner-only file store before any
	// profile or E2EE material is written. Desktop sessions keep using the OS
	// credential store; this does not weaken their storage policy.
	if !cfg.Auth.AllowFileFallback && !config.CredentialStoreAvailable() {
		cfg.Auth.AllowFileFallback = true
		if err := cfg.Save(); err != nil {
			return fmt.Errorf("enable protected file credential storage: %w", err)
		}
	}
	store, err := config.ProfileStoreFor(cfg)
	if err != nil {
		return err
	}
	cred := config.Credential{AccessToken: session.AccessToken, RefreshToken: session.RefreshToken, TokenType: session.TokenType, ExpiresAt: time.Now().UTC().Add(time.Duration(session.ExpiresIn) * time.Second)}
	client := api.New(cfg.ServerURL, cred, nil)
	return installBootstrapCLIWith(ctx, session, cfg.ServerURL, store, cred, client, enrollBootstrapCLIIdentity, bootstrapLocalDaemonInstaller(cfg))
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
	return material.ClientSession != nil && (material.SetupMode == "client" || material.SetupMode == "host")
}

func shouldInstallBootstrapHostRuntime(material bootstrap.Material) bool {
	// Host mode is a superset of client mode. Both roles install the durable
	// hostd and updater services; host mode additionally enables machine-only
	// control and availability components in the platform installer.
	return material.SetupMode == "host" || material.SetupMode == "client"
}
