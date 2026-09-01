package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
	"github.com/pinksaucepasta/paperboat/internal/environmentmanager"
	"github.com/spf13/cobra"
)

func TestEnvironmentControlCommandSurface(t *testing.T) {
	root := newRootCommand()
	for _, path := range [][]string{
		{"env", "init"}, {"env", "enroll"}, {"env", "pending"}, {"env", "approve"},
		{"env", "enrollment", "cancel"},
		{"env", "revoke-host"}, {"env", "revoke-manager"}, {"env", "rotate"},
		{"env", "reset"}, {"env", "reset", "cancel"},
		{"env", "abort"}, {"env", "resume"}, {"env", "recovery", "confirm"},
		{"env", "recovery", "recover"}, {"env", "recovery", "cancel"},
	} {
		command, _, err := root.Find(path)
		if err != nil || command == nil {
			t.Fatalf("find %v: command=%v err=%v", path, command, err)
		}
		if command.Flags().Lookup("value") != nil || command.Flags().Lookup("key") != nil {
			t.Fatalf("%v exposes secret material as a direct flag", path)
		}
	}
}

func TestEnvironmentResetRequiresExactTypedConfirmation(t *testing.T) {
	if err := resetEnvironmentAuthority(newEnvironmentTestCommand(strings.NewReader(""), io.Discard), "account_1", "/tmp/recovery", "RESET ENV account_2"); !errors.Is(err, errUsage) {
		t.Fatalf("mismatched reset confirmation error=%v", err)
	}
}

func TestEnvironmentResetInventoryOutputListsEveryScopeAndName(t *testing.T) {
	machineID := "machine_1"
	var output bytes.Buffer
	err := writeDestructiveResetInventory(&output, api.EnvironmentScopeInventory{
		Schema: api.EnvironmentScopeInventorySchemaV1,
		Scopes: []api.EnvironmentScopeMetadata{
			{Scope: api.EnvironmentVariableScopeGlobal, ScopeState: "active", Names: []string{"A_GLOBAL", "Z_GLOBAL"}},
			{Scope: api.EnvironmentVariableScopeMachine, MachineID: &machineID, ScopeState: "retired", Names: []string{"MACHINE_ONLY"}},
		},
	})
	if err != nil || !strings.Contains(output.String(), "global") || !strings.Contains(output.String(), "A_GLOBAL") || !strings.Contains(output.String(), "machine_1") || !strings.Contains(output.String(), "MACHINE_ONLY") {
		t.Fatalf("reset inventory output=%q err=%v", output.String(), err)
	}
}

func TestEnvironmentInitWritesRecoveryOnceAndClearsMemory(t *testing.T) {
	const recovery = "pb-env-recovery-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var recoveryBacking, confirmedBacking []byte
	var events []string
	manager := fakeEnvironmentControlManager{
		resumeEnrollment: func(context.Context, time.Time) (environmentmanager.EnrollmentResult, error) {
			return environmentmanager.EnrollmentResult{}, environmentmanager.ErrNoPendingEnrollment
		},
		begin: func(_ context.Context, certificate []byte, generation int64, genesis bool, _ time.Time) (environmentmanager.EnrollmentResult, error) {
			if !bytes.Equal(certificate, []byte("pbec")) || generation != 4 || !genesis {
				t.Fatalf("begin certificate=%q generation=%d genesis=%t", certificate, generation, genesis)
			}
			recoveryBacking = []byte(recovery)
			return environmentmanager.EnrollmentResult{RequestID: "envreq_1", SafetyCode: "abcd-efgh-jkmn-pqrs", ExpiresAt: time.Now().Add(time.Minute), Recovery: recoveryBacking, KeyGeneration: 1}, nil
		},
		approve: func(_ context.Context, requestID, safety string, _ time.Time) (environmentmanager.TransitionResult, error) {
			events = append(events, "approve")
			if requestID != "envreq_1" || safety != "abcd-efgh-jkmn-pqrs" {
				t.Fatalf("approve request=%q safety=%q", requestID, safety)
			}
			return environmentmanager.TransitionResult{TransitionID: "sha256:transition", AuthorityID: "sha256:authority", Generation: 1, State: "active"}, nil
		},
		confirm: func(value []byte) error {
			events = append(events, "confirm")
			if !bytes.Equal(value, []byte(recovery)) {
				t.Fatalf("confirm recovery=%q", value)
			}
			confirmedBacking = value
			return nil
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/environment-authority" {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "authority_not_initialized", "message": "not initialized"}})
	}))
	defer server.Close()
	withEnvironmentControlDependencies(t, environmentControlDependencies{client: api.New(server.URL, config.Credential{}, server.Client()), manager: manager, certificate: []byte("pbec"), subjectGeneration: 4})

	path := filepath.Join(t.TempDir(), "environment-recovery.txt")
	var output bytes.Buffer
	if err := initializeEnvironmentAuthority(newEnvironmentTestCommand(strings.NewReader(""), &output), path); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(path)
	if err != nil || string(stored) != recovery+"\n" {
		t.Fatalf("stored recovery=%q err=%v", stored, err)
	}
	clear(stored)
	info, _ := os.Stat(path)
	if info == nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("recovery mode=%v", info)
	}
	if !allZero(recoveryBacking) || !allZero(confirmedBacking) {
		t.Fatal("recovery buffer was not cleared after initialization")
	}
	if !slices.Equal(events, []string{"confirm", "approve"}) {
		t.Fatalf("genesis ordering=%v", events)
	}
	if strings.Contains(output.String(), recovery) || !strings.Contains(output.String(), "recovery key written") || !strings.Contains(output.String(), "is active") {
		t.Fatalf("unsafe init output=%q", output.String())
	}
	if err := writeEnvironmentRecoveryFile(path, []byte("another")); err == nil {
		t.Fatal("existing recovery file was overwritten")
	}
}

func TestEnvironmentInitResumesAfterRecoveryConfirmationWithoutPrivateCopy(t *testing.T) {
	const recovery = "pb-env-recovery-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	path := filepath.Join(t.TempDir(), "environment-recovery.txt")
	if err := os.WriteFile(path, []byte(recovery+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	confirmed, approved := false, false
	manager := fakeEnvironmentControlManager{
		resumeEnrollment: func(context.Context, time.Time) (environmentmanager.EnrollmentResult, error) {
			return environmentmanager.EnrollmentResult{RequestID: "envreq_1", SafetyCode: "abcd-efgh-jkmn-pqrs", RecoveryExportConfirmed: true}, nil
		},
		confirm: func(value []byte) error {
			confirmed = bytes.Equal(value, []byte(recovery))
			return nil
		},
		approve: func(context.Context, string, string, time.Time) (environmentmanager.TransitionResult, error) {
			if !confirmed {
				t.Fatal("approval ran before recovery file verification")
			}
			approved = true
			return environmentmanager.TransitionResult{AuthorityID: "sha256:authority", Generation: 1}, nil
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "authority_not_initialized", "message": "not initialized"}})
	}))
	defer server.Close()
	withEnvironmentControlDependencies(t, environmentControlDependencies{client: api.New(server.URL, config.Credential{}, server.Client()), manager: manager, certificate: []byte("pbec"), subjectGeneration: 1})
	if err := initializeEnvironmentAuthority(newEnvironmentTestCommand(strings.NewReader(""), io.Discard), path); err != nil || !approved {
		t.Fatalf("resume err=%v approved=%t", err, approved)
	}
}

func TestEnvironmentManagerEnrollmentCancelRequiresConfirmation(t *testing.T) {
	canceled := false
	manager := fakeEnvironmentControlManager{cancelEnrollment: func() error { canceled = true; return nil }}
	withEnvironmentControlDependencies(t, environmentControlDependencies{manager: manager, certificate: []byte("pbec"), subjectGeneration: 1})
	command := newEnvironmentTestCommand(strings.NewReader(""), io.Discard)
	if err := cancelEnvironmentManagerEnrollment(command, false); !errors.Is(err, errUsage) || canceled {
		t.Fatalf("unconfirmed cancel err=%v canceled=%t", err, canceled)
	}
	if err := cancelEnvironmentManagerEnrollment(command, true); err != nil || !canceled {
		t.Fatalf("confirmed cancel err=%v canceled=%t", err, canceled)
	}
}

func TestEnvironmentManagerRevocationRequiresExplicitKind(t *testing.T) {
	if _, err := parseEnvironmentManagerKind(""); !errors.Is(err, errUsage) {
		t.Fatalf("missing manager kind error=%v", err)
	}
	if kind, err := parseEnvironmentManagerKind("browser"); err != nil || kind != environmente2ee.SubjectManagerBrowser {
		t.Fatalf("browser manager kind=%v err=%v", kind, err)
	}
	if kind, err := parseEnvironmentManagerKind("cli"); err != nil || kind != environmente2ee.SubjectManagerCLI {
		t.Fatalf("CLI manager kind=%v err=%v", kind, err)
	}
}

func TestEnvironmentPendingOutputIsRedacted(t *testing.T) {
	const publicRequestCanary = "public-enrollment-envelope-not-for-output"
	manager := fakeEnvironmentControlManager{pending: func(context.Context, time.Time) ([]environmentmanager.VerifiedPendingEnrollment, error) {
		return []environmentmanager.VerifiedPendingEnrollment{{
			RequestID: "envreq_1", SafetyCode: "abcd-efgh-jkmn-pqrs", ExpiresAt: time.Unix(10, 0).UTC(),
			Request: environmente2ee.EnrollmentRequest{SubjectKind: environmente2ee.SubjectHost, SubjectID: "machine_1", RecipientKeyID: publicRequestCanary},
		}}, nil
	}}
	withEnvironmentControlDependencies(t, environmentControlDependencies{manager: manager, certificate: []byte("pbec"), subjectGeneration: 1})
	var output bytes.Buffer
	if err := listPendingEnvironmentEnrollments(newEnvironmentTestCommand(strings.NewReader(""), &output), true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), publicRequestCanary) || !strings.Contains(output.String(), "machine_1") || !strings.Contains(output.String(), "abcd-efgh-jkmn-pqrs") {
		t.Fatalf("pending output=%q", output.String())
	}
}

func TestEnvironmentRecoveryFileRejectsLoosePermissionsAndSymlink(t *testing.T) {
	directory := t.TempDir()
	loose := filepath.Join(directory, "loose")
	if err := os.WriteFile(loose, []byte("pb-env-recovery-v1-test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readEnvironmentRecoveryFile(loose); err == nil {
		t.Fatal("loosely permissioned recovery file accepted")
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("pb-env-recovery-v1-test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := readEnvironmentRecoveryFile(link); err == nil {
		t.Fatal("symlinked recovery file accepted")
	}
}

func TestEnvironmentResumeReportsOnlyPublicTransitionMetadata(t *testing.T) {
	manager := fakeEnvironmentControlManager{resume: func(context.Context) (environmentmanager.TransitionResult, error) {
		return environmentmanager.TransitionResult{TransitionID: "sha256:transition", AuthorityID: "sha256:authority", Generation: 8, State: "active"}, nil
	}}
	withEnvironmentControlDependencies(t, environmentControlDependencies{manager: manager, certificate: []byte("pbec"), subjectGeneration: 1})
	var output bytes.Buffer
	if err := resumeEnvironmentTransition(newEnvironmentTestCommand(strings.NewReader(""), &output)); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "sha256:transition") || !strings.Contains(got, "generation 8") {
		t.Fatalf("resume output=%q", got)
	}
}

func TestEnvironmentRecoveryExportsOnceConfirmsAndClears(t *testing.T) {
	const oldRecovery = "pb-env-recovery-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const replacement = "pb-env-recovery-v1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	directory := t.TempDir()
	input := filepath.Join(directory, "old")
	output := filepath.Join(directory, "replacement")
	if err := os.WriteFile(input, []byte(oldRecovery+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var preparationBacking, confirmedBacking []byte
	manager := fakeEnvironmentControlManager{
		resumeRecovery: func() (environmentmanager.RecoveryPreparation, error) {
			return environmentmanager.RecoveryPreparation{}, config.ErrSecretNotFound
		},
		beginRecovery: func(value []byte) (environmentmanager.RecoveryPreparation, error) {
			if !bytes.Equal(value, []byte(oldRecovery)) {
				t.Fatalf("imported recovery=%q", value)
			}
			preparationBacking = []byte(replacement)
			return environmentmanager.RecoveryPreparation{ImportedHandle: "envrec_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReplacementHandle: "envrec_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Recovery: preparationBacking}, nil
		},
		confirmPreparation: func(value []byte) error {
			if !bytes.Equal(value, []byte(replacement)) {
				t.Fatalf("confirmed replacement=%q", value)
			}
			confirmedBacking = value
			return nil
		},
		recover: func(_ context.Context, request environmentmanager.RecoveryRotationRequest) (environmentmanager.TransitionResult, error) {
			if request.ImportedRecoveryHandle != "envrec_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || request.ReplacementRecoveryHandle != "envrec_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" || !bytes.Equal(request.EndpointCertificate, []byte("pbec")) || request.SubjectGeneration != 7 || request.Now.IsZero() {
				t.Fatalf("recovery request=%+v", request)
			}
			return environmentmanager.TransitionResult{TransitionID: "sha256:transition", AuthorityID: "sha256:authority", Generation: 9, State: "active"}, nil
		},
	}
	withEnvironmentControlDependencies(t, environmentControlDependencies{manager: manager, certificate: []byte("pbec"), subjectGeneration: 7})
	var commandOutput bytes.Buffer
	if err := recoverEnvironmentAuthority(newEnvironmentTestCommand(strings.NewReader(""), &commandOutput), input, output); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(output)
	if err != nil || string(stored) != replacement+"\n" {
		t.Fatalf("replacement file=%q err=%v", stored, err)
	}
	clear(stored)
	if !allZero(preparationBacking) || !allZero(confirmedBacking) {
		t.Fatal("recovery buffers were not cleared")
	}
	if got := commandOutput.String(); strings.Contains(got, oldRecovery) || strings.Contains(got, replacement) || !strings.Contains(got, "every scope key was rotated") {
		t.Fatalf("unsafe recovery output=%q", got)
	}

	// A crash after export is resumable only with the exact existing file.
	if err := ensureEnvironmentRecoveryFile(output, []byte(replacement)); err != nil {
		t.Fatalf("verify matching recovery output: %v", err)
	}
	if err := ensureEnvironmentRecoveryFile(output, []byte(oldRecovery)); err == nil {
		t.Fatal("mismatched existing recovery output accepted")
	}
}

func TestEnvironmentRecoveryResumesConfirmedPreparationWithoutOldFile(t *testing.T) {
	const replacement = "pb-env-recovery-v1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	output := filepath.Join(t.TempDir(), "replacement")
	if err := os.WriteFile(output, []byte(replacement+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	beginCalled, confirmCalled := false, false
	manager := fakeEnvironmentControlManager{
		resumeRecovery: func() (environmentmanager.RecoveryPreparation, error) {
			return environmentmanager.RecoveryPreparation{ImportedHandle: "envrec_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReplacementHandle: "envrec_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Recovery: []byte(replacement), ExportConfirmed: true}, nil
		},
		beginRecovery: func([]byte) (environmentmanager.RecoveryPreparation, error) {
			beginCalled = true
			return environmentmanager.RecoveryPreparation{}, errors.New("unexpected begin")
		},
		confirmPreparation: func([]byte) error {
			confirmCalled = true
			return errors.New("unexpected confirm")
		},
		recover: func(context.Context, environmentmanager.RecoveryRotationRequest) (environmentmanager.TransitionResult, error) {
			return environmentmanager.TransitionResult{AuthorityID: "sha256:authority", Generation: 3, State: "active"}, nil
		},
	}
	withEnvironmentControlDependencies(t, environmentControlDependencies{manager: manager, certificate: []byte("pbec"), subjectGeneration: 2})
	if err := recoverEnvironmentAuthority(newEnvironmentTestCommand(strings.NewReader(""), io.Discard), "", output); err != nil {
		t.Fatal(err)
	}
	if beginCalled || confirmCalled {
		t.Fatalf("confirmed resume regenerated=%t reconfirmed=%t", beginCalled, confirmCalled)
	}
}

func TestEnvironmentRecoveryCancelRequiresConfirmation(t *testing.T) {
	canceled := false
	manager := fakeEnvironmentControlManager{cancelRecovery: func() error { canceled = true; return nil }}
	withEnvironmentControlDependencies(t, environmentControlDependencies{manager: manager, certificate: []byte("pbec"), subjectGeneration: 1})
	command := newEnvironmentTestCommand(strings.NewReader(""), io.Discard)
	if err := cancelEnvironmentRecovery(command, false); !errors.Is(err, errUsage) || canceled {
		t.Fatalf("unconfirmed cancel err=%v canceled=%t", err, canceled)
	}
	if err := cancelEnvironmentRecovery(command, true); err != nil || !canceled {
		t.Fatalf("confirmed cancel err=%v canceled=%t", err, canceled)
	}
}

func TestEnvironmentControlErrorsNeverEchoArbitraryDetails(t *testing.T) {
	const canary = "environment-control-error-canary"
	for _, err := range []error{
		errors.New(canary),
		&api.APIError{Code: "transition_in_progress", Message: canary, Details: map[string]any{"secret": canary}},
	} {
		got := safeEnvironmentControlError(err)
		if got == nil || strings.Contains(got.Error(), canary) {
			t.Fatalf("unsafe error=%v", got)
		}
	}
}

func withEnvironmentControlDependencies(t *testing.T, dependencies environmentControlDependencies) {
	t.Helper()
	previous := environmentControlDependenciesForCommand
	environmentControlDependenciesForCommand = func(*cobra.Command) (environmentControlDependencies, error) {
		copy := dependencies
		copy.certificate = append([]byte(nil), dependencies.certificate...)
		return copy, nil
	}
	t.Cleanup(func() { environmentControlDependenciesForCommand = previous })
}

type fakeEnvironmentControlManager struct {
	begin              func(context.Context, []byte, int64, bool, time.Time) (environmentmanager.EnrollmentResult, error)
	resumeEnrollment   func(context.Context, time.Time) (environmentmanager.EnrollmentResult, error)
	cancelEnrollment   func() error
	confirm            func([]byte) error
	beginRecovery      func([]byte) (environmentmanager.RecoveryPreparation, error)
	resumeRecovery     func() (environmentmanager.RecoveryPreparation, error)
	confirmPreparation func([]byte) error
	cancelRecovery     func() error
	recover            func(context.Context, environmentmanager.RecoveryRotationRequest) (environmentmanager.TransitionResult, error)
	pending            func(context.Context, time.Time) ([]environmentmanager.VerifiedPendingEnrollment, error)
	approve            func(context.Context, string, string, time.Time) (environmentmanager.TransitionResult, error)
	apply              func(context.Context, environmentmanager.AuthorityChange) (environmentmanager.TransitionResult, error)
	abort              func(context.Context, string) (environmentmanager.TransitionResult, error)
	resume             func(context.Context) (environmentmanager.TransitionResult, error)
}

func (fake fakeEnvironmentControlManager) BeginManagerEnrollment(ctx context.Context, certificate []byte, generation int64, genesis bool, now time.Time) (environmentmanager.EnrollmentResult, error) {
	if fake.begin == nil {
		return environmentmanager.EnrollmentResult{}, errors.New("unexpected begin")
	}
	return fake.begin(ctx, certificate, generation, genesis, now)
}

func (fake fakeEnvironmentControlManager) ResumeManagerEnrollment(ctx context.Context, now time.Time) (environmentmanager.EnrollmentResult, error) {
	if fake.resumeEnrollment == nil {
		return environmentmanager.EnrollmentResult{}, environmentmanager.ErrNoPendingEnrollment
	}
	return fake.resumeEnrollment(ctx, now)
}

func (fake fakeEnvironmentControlManager) CancelManagerEnrollment() error {
	if fake.cancelEnrollment == nil {
		return errors.New("unexpected enrollment cancel")
	}
	return fake.cancelEnrollment()
}

func (fake fakeEnvironmentControlManager) ConfirmRecoveryExport(value []byte) error {
	if fake.confirm == nil {
		return errors.New("unexpected recovery confirmation")
	}
	return fake.confirm(value)
}

func (fake fakeEnvironmentControlManager) BeginRecoveryPreparation(value []byte) (environmentmanager.RecoveryPreparation, error) {
	if fake.beginRecovery == nil {
		return environmentmanager.RecoveryPreparation{}, errors.New("unexpected recovery preparation")
	}
	return fake.beginRecovery(value)
}

func (fake fakeEnvironmentControlManager) ResumeRecoveryPreparation() (environmentmanager.RecoveryPreparation, error) {
	if fake.resumeRecovery == nil {
		return environmentmanager.RecoveryPreparation{}, errors.New("unexpected recovery preparation resume")
	}
	return fake.resumeRecovery()
}

func (fake fakeEnvironmentControlManager) ConfirmRecoveryPreparationExport(value []byte) error {
	if fake.confirmPreparation == nil {
		return errors.New("unexpected recovery preparation confirmation")
	}
	return fake.confirmPreparation(value)
}

func (fake fakeEnvironmentControlManager) CancelRecoveryPreparation() error {
	if fake.cancelRecovery == nil {
		return errors.New("unexpected recovery preparation cancel")
	}
	return fake.cancelRecovery()
}

func (fake fakeEnvironmentControlManager) RecoverAndRotate(ctx context.Context, request environmentmanager.RecoveryRotationRequest) (environmentmanager.TransitionResult, error) {
	if fake.recover == nil {
		return environmentmanager.TransitionResult{}, errors.New("unexpected recovery rotation")
	}
	return fake.recover(ctx, request)
}

func (fake fakeEnvironmentControlManager) ListVerifiedPendingEnrollments(ctx context.Context, now time.Time) ([]environmentmanager.VerifiedPendingEnrollment, error) {
	if fake.pending == nil {
		return nil, errors.New("unexpected pending list")
	}
	return fake.pending(ctx, now)
}

func (fake fakeEnvironmentControlManager) ApproveEnrollment(ctx context.Context, requestID, safety string, now time.Time) (environmentmanager.TransitionResult, error) {
	if fake.approve == nil {
		return environmentmanager.TransitionResult{}, errors.New("unexpected approval")
	}
	return fake.approve(ctx, requestID, safety, now)
}

func (fake fakeEnvironmentControlManager) ApplyAuthorityChange(ctx context.Context, change environmentmanager.AuthorityChange) (environmentmanager.TransitionResult, error) {
	if fake.apply == nil {
		return environmentmanager.TransitionResult{}, errors.New("unexpected authority change")
	}
	return fake.apply(ctx, change)
}

func (fake fakeEnvironmentControlManager) AbortAuthorityTransition(ctx context.Context, transitionID string) (environmentmanager.TransitionResult, error) {
	if fake.abort == nil {
		return environmentmanager.TransitionResult{}, errors.New("unexpected abort")
	}
	return fake.abort(ctx, transitionID)
}

func (fake fakeEnvironmentControlManager) ResumeAuthorityTransition(ctx context.Context) (environmentmanager.TransitionResult, error) {
	if fake.resume == nil {
		return environmentmanager.TransitionResult{}, errors.New("unexpected transition resume")
	}
	return fake.resume(ctx)
}
