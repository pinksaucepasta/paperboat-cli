package hostruntimecmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releaseindex"
)

func TestOneShotResumeRecoversAmbiguousPairingCommitWithoutToken(t *testing.T) {
	now := time.Now().UTC()
	root := t.TempDir()
	server := "https://api.example.test"
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	token := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP"
	resume, resumeErr := bootstrap.LoadResume(root, server, publicKey, token, "Laptop", "client", now)
	createCalls, waitCalls, consumeCalls := 0, 0, 0
	operations := testOneShotResumeOperations(now)
	operations.WaitForMaterial = func(context.Context, bootstrap.Config, time.Time, time.Duration) (bootstrap.Material, error) {
		waitCalls++
		if waitCalls == 1 {
			return bootstrap.Material{}, bootstrap.ErrInstallationUnavailable
		}
		return testClientBootstrapMaterial(server, now.Add(time.Hour)), nil
	}
	operations.CreatePairing = func(context.Context, bootstrap.Config) (bootstrap.Pairing, error) {
		createCalls++
		return bootstrap.Pairing{}, errors.New("pairing response was lost")
	}
	operations.ConsumeTokenFile = func(string) error {
		consumeCalls++
		return nil
	}
	input := testOneShotResumeInput(root, server, publicKey, token, resume, resumeErr)
	if _, _, err := resumeOneShotEnrollment(context.Background(), input, operations); err == nil || err.Error() != "pairing response was lost" {
		t.Fatalf("first run error = %v", err)
	}
	journal, err := bootstrap.LoadResume(root, server, publicKey, "", "Laptop", "client", now)
	if err != nil || !journal.PairingStarted || journal.Material != nil {
		t.Fatalf("paired journal = %#v, err=%v", journal, err)
	}
	verifier := journal.Verifier
	input = testOneShotResumeInput(root, server, publicKey, "", journal, nil)
	input.TokenFileErr = bootstrap.ErrInvalid
	material, journal, err := resumeOneShotEnrollment(context.Background(), input, operations)
	if err != nil {
		t.Fatal(err)
	}
	if material.UserMachineID != "mch_client" || journal.Verifier != verifier || createCalls != 1 || consumeCalls != 0 {
		t.Fatalf("material=%#v verifier=%q create=%d consume=%d", material, journal.Verifier, createCalls, consumeCalls)
	}
}

func TestOneShotResumeContinuesAfterTokenConsumptionAndApprovalTimeout(t *testing.T) {
	now := time.Now().UTC()
	root := t.TempDir()
	server := "https://api.example.test"
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	token := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP"
	resume, resumeErr := bootstrap.LoadResume(root, server, publicKey, token, "Laptop", "client", now)
	createCalls, waitCalls, consumeCalls := 0, 0, 0
	operations := testOneShotResumeOperations(now)
	operations.WaitForMaterial = func(context.Context, bootstrap.Config, time.Time, time.Duration) (bootstrap.Material, error) {
		waitCalls++
		switch waitCalls {
		case 1:
			return bootstrap.Material{}, bootstrap.ErrInstallationUnavailable
		case 2:
			return bootstrap.Material{}, context.DeadlineExceeded
		default:
			return testClientBootstrapMaterial(server, now.Add(time.Hour)), nil
		}
	}
	operations.CreatePairing = func(context.Context, bootstrap.Config) (bootstrap.Pairing, error) {
		createCalls++
		return bootstrap.Pairing{ID: "pair_1", UserCode: "ABCD-1234", ExpiresAt: now.Add(time.Hour)}, nil
	}
	operations.ConsumeTokenFile = func(string) error {
		consumeCalls++
		return nil
	}
	input := testOneShotResumeInput(root, server, publicKey, token, resume, resumeErr)
	input.TokenFile = filepath.Join(root, "token")
	if _, _, err := resumeOneShotEnrollment(context.Background(), input, operations); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("approval timeout error = %v", err)
	}
	journal, err := bootstrap.LoadResume(root, server, publicKey, "", "Laptop", "client", now)
	if err != nil || !journal.PairingStarted || journal.Material != nil {
		t.Fatalf("journal after timeout = %#v, err=%v", journal, err)
	}
	input = testOneShotResumeInput(root, server, publicKey, "", journal, nil)
	input.TokenFile = filepath.Join(root, "token")
	input.TokenFileErr = bootstrap.ErrInvalid
	material, journal, err := resumeOneShotEnrollment(context.Background(), input, operations)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Material == nil || material.UserMachineID != "mch_client" || createCalls != 1 || consumeCalls != 1 {
		t.Fatalf("journal=%#v create=%d consume=%d", journal, createCalls, consumeCalls)
	}
}

func TestOneShotResumeConsumesTokenLeftAfterMaterialCheckpoint(t *testing.T) {
	now := time.Now().UTC()
	root := t.TempDir()
	server := "https://api.example.test"
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	material := testClientBootstrapMaterial(server, now.Add(time.Hour))
	record := bootstrap.NewResumeRecord(server, publicKey, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP", "Laptop", "client", "verifier-012345678901234567890123456789", now.Add(time.Hour))
	record.PairingStarted, record.Material = true, &material
	if err := bootstrap.SaveResume(root, record); err != nil {
		t.Fatal(err)
	}
	consumeCalls := 0
	operations := testOneShotResumeOperations(now)
	operations.ConsumeTokenFile = func(string) error {
		consumeCalls++
		return nil
	}
	input := testOneShotResumeInput(root, server, publicKey, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP", record, nil)
	input.TokenFile = filepath.Join(root, "token")
	got, _, err := resumeOneShotEnrollment(context.Background(), input, operations)
	if err != nil || got.UserMachineID != material.UserMachineID || consumeCalls != 1 {
		t.Fatalf("material=%#v consume=%d err=%v", got, consumeCalls, err)
	}
}

func TestUnixBootstrapRejectsUnknownSetupModeBeforeEnrollment(t *testing.T) {
	err := runBootstrap(context.Background(), []string{"--setup-mode", "session"}, nil, nil, nil)
	if err == nil || err.Error() != "setup-mode must be host or client" {
		t.Fatalf("setup mode error = %v", err)
	}
}

func TestBootstrapCLIResumeRetriesTimeoutAndCrashBeforeCheckpoint(t *testing.T) {
	now := time.Now().UTC()
	root := t.TempDir()
	server := "https://api.example.test"
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	material := testClientBootstrapMaterial(server, now.Add(time.Hour))
	record := bootstrap.NewResumeRecord(server, publicKey, "token", "Laptop", "client", "verifier-012345678901234567890123456789", now.Add(time.Hour))
	record.PairingStarted, record.Material = true, &material
	if err := bootstrap.SaveResume(root, record); err != nil {
		t.Fatal(err)
	}
	installCalls := 0
	install := func(context.Context, *bootstrap.ClientSession, string) error {
		installCalls++
		if installCalls == 1 {
			return context.DeadlineExceeded
		}
		return nil
	}
	if err := completeBootstrapCLIResume(context.Background(), root, server, material, &record, install, bootstrap.SaveResume); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("approval error = %v", err)
	}
	reloaded, err := bootstrap.LoadResume(root, server, publicKey, "", "Laptop", "client", now)
	if err != nil || reloaded.ClientInstalled {
		t.Fatalf("checkpoint after timeout = %#v, err=%v", reloaded, err)
	}
	crash := errors.New("simulated crash before checkpoint")
	if err := completeBootstrapCLIResume(context.Background(), root, server, material, &reloaded, install, func(string, bootstrap.ResumeRecord) error { return crash }); !errors.Is(err, crash) {
		t.Fatalf("simulated crash error = %v", err)
	}
	reloaded, err = bootstrap.LoadResume(root, server, publicKey, "", "Laptop", "client", now)
	if err != nil || reloaded.ClientInstalled {
		t.Fatalf("durable checkpoint after crash = %#v, err=%v", reloaded, err)
	}
	if err := completeBootstrapCLIResume(context.Background(), root, server, material, &reloaded, install, bootstrap.SaveResume); err != nil {
		t.Fatal(err)
	}
	reloaded, err = bootstrap.LoadResume(root, server, publicKey, "", "Laptop", "client", now)
	if err != nil || !reloaded.ClientInstalled || installCalls != 3 {
		t.Fatalf("completed checkpoint = %#v, calls=%d, err=%v", reloaded, installCalls, err)
	}
}

func TestAuthenticatedSetupRecoveryNeverCreatesPairingAndPreservesFailedJournal(t *testing.T) {
	now := time.Now().UTC()
	server := "https://api.example.test"
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, test := range []struct {
		name    string
		expired bool
		wantErr error
	}{
		{name: "unavailable", wantErr: bootstrap.ErrInstallationUnavailable},
		{name: "expired", expired: true, wantErr: bootstrap.ErrResumeExpired},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			expiresAt := now.Add(time.Hour)
			if test.expired {
				expiresAt = now.Add(-time.Minute)
			}
			record := bootstrap.NewResumeRecord(server, publicKey, "", "Laptop", "host", "verifier-012345678901234567890123456789", expiresAt)
			record.AuthenticatedSetup = true
			record.SetupOperationID = "host-setup-operation"
			record.ExpectedUserMachineID = "mch_host"
			record.ExpectedGeneration = 7
			record.PairingStarted = test.expired
			if err := bootstrap.SaveResume(root, record); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(bootstrap.ResumePath(root))
			if err != nil {
				t.Fatal(err)
			}
			loaded, loadErr := bootstrap.LoadResume(root, server, publicKey, "", "Laptop", "host", now)
			if test.expired != errors.Is(loadErr, bootstrap.ErrResumeExpired) || !test.expired && loadErr != nil {
				t.Fatalf("load error = %v", loadErr)
			}
			createCalls, recoverCalls := 0, 0
			operations := testOneShotResumeOperations(now)
			operations.CreatePairing = func(context.Context, bootstrap.Config) (bootstrap.Pairing, error) {
				createCalls++
				return bootstrap.Pairing{}, errors.New("authenticated recovery called CreatePairing")
			}
			operations.RecoverMaterial = func(context.Context, bootstrap.Config, bool) (bootstrap.Material, error) {
				recoverCalls++
				return bootstrap.Material{}, bootstrap.ErrInstallationUnavailable
			}
			config := bootstrap.Config{ServerURL: server, DisplayName: "Laptop", WorkspaceRoot: root, Verifier: loaded.Verifier, PublicIdentityKey: publicKey}
			if _, err := recoverAuthenticatedSetupMaterial(context.Background(), config, loaded, test.expired, operations); !errors.Is(err, test.wantErr) {
				t.Fatalf("recovery error = %v, want %v", err, test.wantErr)
			}
			after, err := os.ReadFile(bootstrap.ResumePath(root))
			if err != nil {
				t.Fatal(err)
			}
			if createCalls != 0 || recoverCalls != 1 || !bytes.Equal(before, after) {
				t.Fatalf("create=%d recover=%d journal_changed=%t", createCalls, recoverCalls, !bytes.Equal(before, after))
			}
		})
	}
}

func testOneShotResumeOperations(now time.Time) oneShotResumeOperations {
	operations := defaultOneShotResumeOperations()
	operations.Now = func() time.Time { return now }
	operations.NewVerifier = func() (string, error) { return "verifier-012345678901234567890123456789", nil }
	operations.SaveResume = bootstrap.SaveResume
	operations.ClearResume = bootstrap.ClearResume
	operations.RecoverMaterial = func(context.Context, bootstrap.Config, bool) (bootstrap.Material, error) {
		return bootstrap.Material{}, bootstrap.ErrInstallationUnavailable
	}
	return operations
}

func testOneShotResumeInput(root, server, publicKey, token string, resume bootstrap.ResumeRecord, resumeErr error) oneShotResumeInput {
	return oneShotResumeInput{
		StateRoot: root, SetupMode: "client",
		Config: bootstrap.Config{ServerURL: server, EnrollmentToken: token, DisplayName: "Laptop", WorkspaceRoot: root, PublicIdentityKey: publicKey},
		Resume: resume, ResumeErr: resumeErr, PollInterval: time.Millisecond,
	}
}

func testClientBootstrapMaterial(server string, expiresAt time.Time) bootstrap.Material {
	return bootstrap.Material{
		Schema: "paperboat.byod-installation/v1", UserMachineID: "mch_client", UserMachineEnrollmentID: "ume_client", EnvironmentID: "env_client",
		ControlURL: server, HelperID: "helper_client", EnrollmentID: "henr_client", EnrollmentCredential: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP",
		ExpiresAt: expiresAt, Artifact: &bootstrap.ArtifactTarget{Schema: bootstrap.ArtifactTargetSchemaV1, Kind: bootstrap.ArtifactKindPB, Version: "2026.08.24.1", Platform: runtime.GOOS, Architecture: runtime.GOARCH, RepositoryURL: server, TargetPath: releaseindex.AssetName(runtime.GOOS, runtime.GOARCH)},
		HelperListenAddress: "127.0.0.1:38080", InstallationGeneration: 1, SetupRoles: []string{"interactive"}, SetupMode: "client",
		ClientSession: &bootstrap.ClientSession{Schema: "paperboat.cli-session/v1", SessionID: "cli_client", AccessToken: "access-012345678901234567890123456789", RefreshToken: "refresh-012345678901234567890123456789", TokenType: "Bearer", ExpiresIn: 3600, Scope: "machines:read projects:read projects:connect"},
	}
}
