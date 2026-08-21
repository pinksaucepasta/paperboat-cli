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

// installBootstrapCLI completes the user side of a one-shot enrollment. Host
// credentials and CLI credentials are separate; the latter are stored through
// the normal profile secret store and never written to installation state.
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
	me, err := client.Me(ctx)
	if err != nil {
		return fmt.Errorf("validate CLI session: %w", err)
	}
	profile := config.Profile{Issuer: cfg.ServerURL, Account: config.Account{ID: me.ID, Email: me.Email, DisplayName: me.DisplayName}, CLIClientSessionID: session.SessionID, AccessExpiresAt: cred.ExpiresAt}
	if err := store.Save(profile, cred); err != nil {
		return err
	}
	if _, err := identitybootstrap.Bootstrap(ctx, identitybootstrap.Request{Store: store, Client: client, Issuer: cfg.ServerURL, AccountID: me.ID, CLIClientSessionID: session.SessionID}); err != nil {
		return fmt.Errorf("bootstrap CLI peer identity: %w", err)
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	return localdaemon.InstallCurrentUserService(ctx, executable, cfg.Path(), cfg.ServerURL)
}
