package updated

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type recordingWindowsActivationBackend struct {
	events             []string
	fail               string
	stoppedLocalDaemon bool
	startedLocalDaemon bool
}

func (b *recordingWindowsActivationBackend) event(name string) error {
	b.events = append(b.events, name)
	if b.fail == name {
		return errors.New("injected " + name)
	}
	return nil
}
func (b *recordingWindowsActivationBackend) WriteJournal(j windowsActivationJournal) error {
	return b.event("journal:" + string(j.Stage))
}
func (b *recordingWindowsActivationBackend) StopServices(_ context.Context, localDaemon bool) error {
	b.stoppedLocalDaemon = b.stoppedLocalDaemon || localDaemon
	return b.event("stop")
}
func (b *recordingWindowsActivationBackend) ActivateBinary(_ context.Context, _ windowsActivationJournal) error {
	return b.event("activate")
}
func (b *recordingWindowsActivationBackend) RestoreBinary(_ context.Context, _ windowsActivationJournal) error {
	return b.event("restore")
}
func (b *recordingWindowsActivationBackend) SetServiceTargets(_ context.Context, h, _, _ windowsServiceTarget) error {
	return b.event("targets:" + h.Executable)
}
func (b *recordingWindowsActivationBackend) StartServices(_ context.Context, h, u, ssh, localDaemon bool) error {
	b.startedLocalDaemon = b.startedLocalDaemon || localDaemon
	return b.event("start")
}
func (b *recordingWindowsActivationBackend) VerifyHealth(context.Context, windowsActivationJournal) error {
	return b.event("health")
}
func (b *recordingWindowsActivationBackend) CommitCLI(_ context.Context, j windowsActivationJournal) error {
	return b.event("cli:" + j.NewCLIRecord)
}
func (b *recordingWindowsActivationBackend) Quarantine(context.Context, windowsActivationJournal) error {
	return b.event("quarantine")
}
func (b *recordingWindowsActivationBackend) FinalizeServices(_ context.Context, _ windowsActivationJournal) error {
	b.startedLocalDaemon = true
	return b.event("finalize")
}

func testWindowsActivationJournal() windowsActivationJournal {
	c := windowsActivationComponent{Path: `C:\Paperboat\candidate.exe`, SHA256: strings.Repeat("a", 64), Length: 1}
	previous := c
	previous.Path = `C:\Program Files\Paperboat\bin\pb.exe`
	return windowsActivationJournal{Schema: windowsActivationJournalSchema, TransactionID: strings.Repeat("1", 32), PreviousVersion: "2026.08.22.1", Version: "2026.08.23.1", Architecture: "amd64", Stage: windowsActivationStaged, Runtime: c, CLI: c, Hostd: c, Updater: c, PreviousBinary: previous, OldHostd: windowsServiceTarget{Executable: `C:\Program Files\Paperboat\bin\pb.exe`, Arguments: []string{"__runtime-hostd"}, WasRunning: true}, NewHostd: windowsServiceTarget{Executable: `C:\Program Files\Paperboat\bin\pb.exe`, Arguments: []string{"__runtime-hostd"}}, OldUpdater: windowsServiceTarget{Executable: `C:\Program Files\Paperboat\bin\pb.exe`, Arguments: []string{"__runtime-updated"}, WasRunning: true}, NewUpdater: windowsServiceTarget{Executable: `C:\Program Files\Paperboat\bin\pb.exe`, Arguments: []string{"__runtime-updated"}}}
}

func TestWindowsActivationCommitsCLIOnlyAfterHealth(t *testing.T) {
	b := &recordingWindowsActivationBackend{}
	result, err := executeWindowsActivation(context.Background(), b, testWindowsActivationJournal())
	if err != nil || result.Stage != windowsActivationCommitted {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	want := []string{"journal:switching", "stop", "activate", "targets:C:\\Program Files\\Paperboat\\bin\\pb.exe", "start", "journal:services_live", "health", "cli:", "journal:committed", "finalize"}
	if !reflect.DeepEqual(b.events, want) {
		t.Fatalf("events=%q want=%q", b.events, want)
	}
}

func TestWindowsActivationSuspendsAndRestartsRecordedLocalDaemon(t *testing.T) {
	b := &recordingWindowsActivationBackend{}
	journal := testWindowsActivationJournal()
	journal.LocalDaemonWasRunning = true
	result, err := executeWindowsActivation(context.Background(), b, journal)
	if err != nil || result.Stage != windowsActivationCommitted {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !b.stoppedLocalDaemon || !b.startedLocalDaemon {
		t.Fatalf("local daemon lifecycle: stopped=%t started=%t", b.stoppedLocalDaemon, b.startedLocalDaemon)
	}
}

func TestWindowsActivationHealthFailureRestoresExactOldTargetsAndCLI(t *testing.T) {
	b := &recordingWindowsActivationBackend{fail: "health"}
	result, err := executeWindowsActivation(context.Background(), b, testWindowsActivationJournal())
	if err == nil || result.Stage != windowsActivationRolledBack {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	wantTail := []string{"journal:rolling_back", "stop", "restore", "targets:C:\\Program Files\\Paperboat\\bin\\pb.exe", "cli:", "quarantine", "journal:rollback_ready", "start", "journal:rolled_back"}
	if !reflect.DeepEqual(b.events[len(b.events)-len(wantTail):], wantTail) {
		t.Fatalf("events=%q", b.events)
	}
}

func TestWindowsActivationRollbackReadyResumeOnlyStartsOldServices(t *testing.T) {
	journal := testWindowsActivationJournal()
	journal.Stage = windowsActivationRollbackReady
	b := &recordingWindowsActivationBackend{}
	result, err := executeWindowsActivation(context.Background(), b, journal)
	if err == nil || result.Stage != windowsActivationRolledBack {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	want := []string{"start", "journal:rolled_back"}
	if !reflect.DeepEqual(b.events, want) {
		t.Fatalf("events=%q want=%q", b.events, want)
	}
}

func TestWindowsActivationDoesNotStartOldUpdaterBeforeRollbackReadyIsDurable(t *testing.T) {
	b := &recordingWindowsActivationBackend{fail: "journal:rollback_ready"}
	result, err := rollbackWindowsActivation(context.Background(), b, testWindowsActivationJournal(), errors.New("candidate failed"))
	if err == nil || result.Stage != windowsActivationRollbackReady || slices.Contains(b.events, "start") {
		t.Fatalf("result=%+v events=%q err=%v", result, b.events, err)
	}
}

func TestWindowsActivationRollbackStartsServicesWhenCleanupFails(t *testing.T) {
	b := &recordingWindowsActivationBackend{fail: "quarantine"}
	result, err := rollbackWindowsActivation(context.Background(), b, testWindowsActivationJournal(), errors.New("candidate failed"))
	if err == nil || result.Stage != windowsActivationRolledBack {
		t.Fatalf("result=%+v events=%q err=%v", result, b.events, err)
	}
	if !slices.Contains(b.events, "start") {
		t.Fatalf("services were not restarted after non-critical cleanup failure: %q", b.events)
	}
}

func TestWindowsActivationFailureIsBoundedAndSingleLine(t *testing.T) {
	message := boundedWindowsActivationFailure(errors.New(strings.Repeat("x", 3000) + "\r\nsecret"))
	if len(message) != 2048 || strings.ContainsAny(message, "\r\n\x00") {
		t.Fatalf("failure length=%d value=%q", len(message), message)
	}
}

func TestWindowsActivationRecoveryNeverContinuesAmbiguousCutover(t *testing.T) {
	j := testWindowsActivationJournal()
	j.Stage = windowsActivationServicesLive
	b := &recordingWindowsActivationBackend{}
	result, err := executeWindowsActivation(context.Background(), b, j)
	if err == nil || result.Stage != windowsActivationRolledBack || b.events[0] != "journal:rolling_back" {
		t.Fatalf("result=%+v events=%q err=%v", result, b.events, err)
	}
}

func TestWindowsActivationRollbackNeverRestartsAfterTargetFailure(t *testing.T) {
	b := &recordingWindowsActivationBackend{fail: `targets:C:\Program Files\Paperboat\bin\pb.exe`}
	result, err := rollbackWindowsActivation(context.Background(), b, testWindowsActivationJournal(), errors.New("candidate failed"))
	if err == nil || result.Stage != windowsActivationRollingBack {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if slices.Contains(b.events, "start") {
		t.Fatalf("unsafe restart after target failure: %q", b.events)
	}
}

func TestWindowsActivationServiceSetIsRoleScoped(t *testing.T) {
	if got, want := windowsActivationServiceNames("client"), []string{"PaperboatHostd", "PaperboatUpdated"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("client=%q want=%q", got, want)
	}
	if got, want := windowsActivationServiceNames("host"), []string{"PaperboatSshd", "PaperboatHostd", "PaperboatUpdated"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("host=%q want=%q", got, want)
	}
	if got, want := windowsActivationServiceStartNames("host", true, true, true), []string{"PaperboatSshd", "PaperboatHostd", "PaperboatUpdated"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("host start order=%q want=%q", got, want)
	}
	if got, want := windowsActivationServiceStartNames("client", true, true, true), []string{"PaperboatHostd", "PaperboatUpdated"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("client start order=%q want=%q", got, want)
	}
	if got, want := windowsActivationServiceStartNames("host", false, true, true), []string{"PaperboatSshd", "PaperboatUpdated"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("filtered host start order=%q want=%q", got, want)
	}
	sshArguments := []string{"__windows-sshd-service", "--sshd", `C:\Program Files\OpenSSH\sshd.exe`, "--config", `C:\ProgramData\Paperboat\ssh\sshd_config`}
	target := windowsServiceTarget{Executable: "sshd", Arguments: sshArguments}
	if !validWindowsSSHRoleTarget("host", target) || validWindowsSSHRoleTarget("host", windowsServiceTarget{}) || validWindowsSSHRoleTarget("client", target) || !validWindowsSSHRoleTarget("client", windowsServiceTarget{}) {
		t.Fatal("PaperboatSshd role invariant is not exact")
	}
	journal := testWindowsActivationJournal()
	journal.OldSSH, journal.NewSSH = target, target
	if !validWindowsActivationJournal(journal) {
		t.Fatal("exact PaperboatSshd journal rejected")
	}
	journal.NewSSH.Arguments = append([]string(nil), sshArguments...)
	journal.NewSSH.Arguments[2] = `C:\Temp\sshd.exe`
	if validWindowsActivationJournal(journal) {
		t.Fatal("malformed PaperboatSshd journal accepted")
	}
}

func TestWindowsActivationBlocksBothSidesUntilTerminalJournal(t *testing.T) {
	journal := testWindowsActivationJournal()
	for _, stage := range []windowsActivationStage{windowsActivationStaged, windowsActivationSwitching, windowsActivationServicesLive, windowsActivationRollingBack} {
		journal.Stage = stage
		if !windowsActivationBlocksVersion(journal, journal.Version) || !windowsActivationBlocksVersion(journal, journal.PreviousVersion) {
			t.Fatalf("stage %q did not fence both updater versions", stage)
		}
	}
	journal.Stage = windowsActivationCommitted
	if windowsActivationBlocksVersion(journal, journal.Version) {
		t.Fatal("committed activation remains fenced")
	}
}

func TestWindowsUpdaterDoesNotResumeTransactionOwnedByRunningActivator(t *testing.T) {
	journal := testWindowsActivationJournal()
	for _, stage := range []windowsActivationStage{windowsActivationSwitching, windowsActivationServicesLive, windowsActivationRollingBack, windowsActivationRollbackReady} {
		journal.Stage = stage
		if windowsActivationNeedsResume(journal, journal.PreviousVersion, true) {
			t.Fatalf("stage %q resumed while activator owned transaction", stage)
		}
		if !windowsActivationNeedsResume(journal, journal.PreviousVersion, false) {
			t.Fatalf("stage %q did not resume after activator stopped", stage)
		}
	}
	journal.Stage = windowsActivationCommitted
	if windowsActivationNeedsResume(journal, journal.PreviousVersion, false) {
		t.Fatal("committed transaction resumed")
	}
	journal.Stage = windowsActivationStaged
	if windowsActivationNeedsResume(journal, journal.Version, false) {
		t.Fatal("active candidate version resumed its own transaction")
	}
}
