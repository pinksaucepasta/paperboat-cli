package hostruntimecmd

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
)

func TestShouldInstallBootstrapCLI(t *testing.T) {
	session := &bootstrap.ClientSession{Schema: "paperboat.cli-session/v1"}
	if !shouldInstallBootstrapCLI(bootstrap.Material{SetupMode: "host", ClientSession: session}) {
		t.Fatal("host enrollment must bootstrap the local CLI identity")
	}
	if !shouldInstallBootstrapCLI(bootstrap.Material{SetupMode: "client", ClientSession: session}) {
		t.Fatal("client enrollment must bootstrap the local CLI identity")
	}
	if shouldInstallBootstrapCLI(bootstrap.Material{SetupMode: "client"}) {
		t.Fatal("enrollment without a CLI session must not bootstrap one")
	}
}

func TestBootstrapCLIHostEnrollmentInstallsClientProfileAndDaemon(t *testing.T) {
	store := testBootstrapProfileStore(t)
	issuer := "https://api.example.test"
	resume := bootstrap.NewResumeRecord(issuer, "public-key", "token", "Victus", "host", "verifier-012345678901234567890123456789", time.Now().UTC().Add(time.Hour))
	material := bootstrap.Material{SetupMode: "host", ClientSession: testBootstrapSession("cli_host")}
	installCalls := 0
	if err := completeBootstrapCLIResume(context.Background(), store.Path, issuer, material, &resume, func(_ context.Context, session *bootstrap.ClientSession, serverURL string) error {
		installCalls++
		if session == nil || session.SessionID != "cli_host" || serverURL != issuer {
			t.Fatalf("client bootstrap args = session=%#v server=%q", session, serverURL)
		}
		return nil
	}, bootstrap.SaveResume); err != nil {
		t.Fatal(err)
	}
	if installCalls != 1 || !resume.ClientInstalled {
		t.Fatalf("installCalls=%d clientInstalled=%t", installCalls, resume.ClientInstalled)
	}
	if _, err := os.Stat(bootstrap.ResumePath(store.Path)); err != nil {
		t.Fatalf("host resume checkpoint was not persisted: %v", err)
	}
}

func TestBootstrapCLISameAccountReplacementQueuesOldSession(t *testing.T) {
	store := testBootstrapProfileStore(t)
	issuer := "https://api.example.test"
	if err := store.Save(config.Profile{Issuer: issuer, Account: config.Account{ID: "account_1"}, CLIClientSessionID: "cli_old"}, testBootstrapCredential("old")); err != nil {
		t.Fatal(err)
	}
	identityCalls := 0
	daemonCalls := 0
	err := installBootstrapCLIWith(context.Background(), testBootstrapSession("cli_new"), issuer, store, testBootstrapCredential("new"), bootstrapClientStub{me: api.Me{ID: "account_1", Email: "admin@example.test"}}, func(_ context.Context, gotStore config.ProfileStore, _ bootstrapCLIClient, gotIssuer string, me api.Me, sessionID string) error {
		identityCalls++
		if gotStore.Path != store.Path || gotIssuer != issuer || me.ID != "account_1" || sessionID != "cli_new" {
			t.Fatalf("identity enrollment arguments = store=%q issuer=%q account=%q session=%q", gotStore.Path, gotIssuer, me.ID, sessionID)
		}
		return nil
	}, func(context.Context) error {
		daemonCalls++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if identityCalls != 1 || daemonCalls != 1 {
		t.Fatalf("identity calls=%d daemon calls=%d", identityCalls, daemonCalls)
	}
	profile, err := store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Account.ID != "account_1" || profile.CLIClientSessionID != "cli_new" {
		t.Fatalf("profile = %#v", profile)
	}
	credential, err := store.CredentialFor(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if credential.RefreshToken != "refresh-new" {
		t.Fatalf("active credential = %#v", credential)
	}
	pending, err := store.PendingRevocations(issuer)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending = %#v, err = %v", pending, err)
	}
	old, err := store.PendingRevocationCredential(pending[0])
	if err != nil {
		t.Fatal(err)
	}
	if pending[0].CLIClientSessionID != "cli_old" || pending[0].AccountID != "account_1" || old.RefreshToken != "refresh-old" {
		t.Fatalf("pending = %#v, credential = %#v", pending[0], old)
	}
}

func TestBootstrapProfileMutationReconcilesCommittedError(t *testing.T) {
	store := testBootstrapProfileStore(t)
	profile := config.Profile{Issuer: "https://api.example.test", Account: config.Account{ID: "account_1"}, CLIClientSessionID: "cli_new"}
	credential := testBootstrapCredential("new")
	if err := store.Save(profile, credential); err != nil {
		t.Fatal(err)
	}
	if err := reconcileBootstrapProfileMutation(store, profile, credential, errors.New("injected post-commit lock failure")); err != nil {
		t.Fatalf("committed bootstrap mutation was rejected: %v", err)
	}
	if err := reconcileBootstrapProfileMutation(store, profile, testBootstrapCredential("different"), errors.New("real failure")); err == nil {
		t.Fatal("mismatched credential suppressed a real bootstrap failure")
	}
}

func TestBootstrapCLIRejectsCrossAccountReplacement(t *testing.T) {
	store := testBootstrapProfileStore(t)
	issuer := "https://api.example.test"
	if err := store.Save(config.Profile{Issuer: issuer, Account: config.Account{ID: "account_old"}, CLIClientSessionID: "cli_old"}, testBootstrapCredential("old")); err != nil {
		t.Fatal(err)
	}
	identityCalls := 0
	err := installBootstrapCLIWith(context.Background(), testBootstrapSession("cli_new"), issuer, store, testBootstrapCredential("new"), bootstrapClientStub{me: api.Me{ID: "account_new"}}, func(context.Context, config.ProfileStore, bootstrapCLIClient, string, api.Me, string) error {
		identityCalls++
		return nil
	}, func(context.Context) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "another account") {
		t.Fatalf("error = %v", err)
	}
	if identityCalls != 0 {
		t.Fatalf("identity calls = %d", identityCalls)
	}
	profile, err := store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Account.ID != "account_old" || profile.CLIClientSessionID != "cli_old" {
		t.Fatalf("profile = %#v", profile)
	}
	pending, err := store.PendingRevocations(issuer)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending = %#v, err = %v", pending, err)
	}
}

func TestBootstrapCLISameSessionReplayDoesNotQueueRevocation(t *testing.T) {
	store := testBootstrapProfileStore(t)
	issuer := "https://api.example.test"
	if err := store.Save(config.Profile{Issuer: issuer, Account: config.Account{ID: "account_1"}, CLIClientSessionID: "cli_same"}, testBootstrapCredential("old")); err != nil {
		t.Fatal(err)
	}
	err := installBootstrapCLIWith(context.Background(), testBootstrapSession("cli_same"), issuer, store, testBootstrapCredential("new"), bootstrapClientStub{me: api.Me{ID: "account_1"}}, func(context.Context, config.ProfileStore, bootstrapCLIClient, string, api.Me, string) error {
		return nil
	}, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.CredentialFor(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if credential.RefreshToken != "refresh-new" {
		t.Fatalf("credential = %#v", credential)
	}
	pending, err := store.PendingRevocations(issuer)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending = %#v, err = %v", pending, err)
	}
}

func TestBootstrapCLIPartialEnrollmentRetryKeepsNewSessionAndPendingRevocation(t *testing.T) {
	store := testBootstrapProfileStore(t)
	issuer := "https://api.example.test"
	if err := store.Save(config.Profile{Issuer: issuer, Account: config.Account{ID: "account_1"}, CLIClientSessionID: "cli_old"}, testBootstrapCredential("old")); err != nil {
		t.Fatal(err)
	}
	approvalPending := errors.New("paired device approval is pending")
	client := bootstrapClientStub{me: api.Me{ID: "account_1"}}
	err := installBootstrapCLIWith(context.Background(), testBootstrapSession("cli_new"), issuer, store, testBootstrapCredential("new"), client, func(context.Context, config.ProfileStore, bootstrapCLIClient, string, api.Me, string) error {
		return approvalPending
	}, func(context.Context) error {
		t.Fatal("daemon installation must wait for identity enrollment")
		return nil
	})
	if !errors.Is(err, approvalPending) {
		t.Fatalf("first enrollment error = %v", err)
	}
	profile, err := store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if profile.CLIClientSessionID != "cli_new" {
		t.Fatalf("profile after partial enrollment = %#v", profile)
	}
	daemonCalls := 0
	err = installBootstrapCLIWith(context.Background(), testBootstrapSession("cli_new"), issuer, store, testBootstrapCredential("new"), client, func(context.Context, config.ProfileStore, bootstrapCLIClient, string, api.Me, string) error {
		return nil
	}, func(context.Context) error {
		daemonCalls++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if daemonCalls != 1 {
		t.Fatalf("daemon calls = %d", daemonCalls)
	}
	pending, err := store.PendingRevocations(issuer)
	if err != nil || len(pending) != 1 || pending[0].CLIClientSessionID != "cli_old" {
		t.Fatalf("pending = %#v, err = %v", pending, err)
	}
}

func testBootstrapProfileStore(t *testing.T) config.ProfileStore {
	t.Helper()
	dir := t.TempDir()
	return config.ProfileStore{Path: dir, Secrets: config.FileSecretStore{Dir: dir + "/secrets"}}
}

func testBootstrapSession(id string) *bootstrap.ClientSession {
	return &bootstrap.ClientSession{Schema: "paperboat.cli-session/v1", SessionID: id, AccessToken: "access-" + id, RefreshToken: "refresh-" + id, TokenType: "Bearer", ExpiresIn: 3600}
}

func testBootstrapCredential(label string) config.Credential {
	return config.Credential{AccessToken: "access-" + label, RefreshToken: "refresh-" + label, TokenType: "Bearer", ExpiresAt: time.Now().UTC().Add(time.Hour)}
}

type bootstrapClientStub struct{ me api.Me }

func (c bootstrapClientStub) Me(context.Context) (api.Me, error) { return c.me, nil }
func (bootstrapClientStub) E2EERoot(context.Context) (api.E2EERoot, error) {
	return api.E2EERoot{}, errors.New("not used by this test")
}
func (bootstrapClientStub) BootstrapE2EE(context.Context, string, api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
	return api.E2EEBootstrapResult{}, errors.New("not used by this test")
}
func (bootstrapClientStub) RequestCLIEndpoint(context.Context, api.CLIEndpointRequestInput) (api.PendingEndpointIdentity, error) {
	return api.PendingEndpointIdentity{}, errors.New("not used by this test")
}
func (bootstrapClientStub) EndpointCertificate(context.Context, string, uint64) (api.EndpointCertificateDocument, error) {
	return api.EndpointCertificateDocument{}, errors.New("not used by this test")
}
