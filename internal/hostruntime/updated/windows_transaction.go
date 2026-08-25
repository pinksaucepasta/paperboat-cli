package updated

import (
	"context"
	"errors"
	"strings"
	"time"
)

const windowsActivationJournalSchema = "paperboat.windows-activation/v1"
const maxWindowsComponentSize int64 = 256 << 20

type windowsActivationStage string

const (
	windowsActivationStaged        windowsActivationStage = "staged"
	windowsActivationSwitching     windowsActivationStage = "switching"
	windowsActivationServicesLive  windowsActivationStage = "services_live"
	windowsActivationCommitted     windowsActivationStage = "committed"
	windowsActivationRollingBack   windowsActivationStage = "rolling_back"
	windowsActivationRollbackReady windowsActivationStage = "rollback_ready"
	windowsActivationRolledBack    windowsActivationStage = "rolled_back"
)

type windowsActivationComponent struct {
	Path, SHA256 string
	Length       int64
}

type windowsServiceTarget struct {
	Executable string   `json:"executable"`
	Arguments  []string `json:"arguments"`
	WasRunning bool     `json:"was_running"`
}

type windowsActivationJournal struct {
	Schema, TransactionID, PreviousVersion, Version, Architecture string
	Stage                                                         windowsActivationStage
	Runtime, CLI, Hostd, Updater, PreviousBinary                  windowsActivationComponent
	OldHostd, NewHostd, OldUpdater, NewUpdater, OldSSH, NewSSH    windowsServiceTarget
	PreviousCLIRecord, NewCLIRecord                               string
	Failure                                                       string
}

var errInvalidWindowsActivation = errors.New("invalid Windows activation transaction")

// windowsActivationBackend is deliberately narrow so the crash choreography
// has deterministic tests without pretending a macOS filesystem models SCM.
type windowsActivationBackend interface {
	WriteJournal(windowsActivationJournal) error
	StopServices(context.Context) error
	ActivateBinary(context.Context, windowsActivationJournal) error
	RestoreBinary(context.Context, windowsActivationJournal) error
	SetServiceTargets(context.Context, windowsServiceTarget, windowsServiceTarget, windowsServiceTarget) error
	StartServices(context.Context, bool, bool, bool) error
	VerifyHealth(context.Context, windowsActivationJournal) error
	CommitCLI(context.Context, windowsActivationJournal) error
	Quarantine(context.Context, windowsActivationJournal) error
}

func executeWindowsActivation(ctx context.Context, backend windowsActivationBackend, journal windowsActivationJournal) (result windowsActivationJournal, err error) {
	if backend == nil || !validWindowsActivationJournal(journal) {
		return journal, errInvalidWindowsActivation
	}
	if journal.Stage == windowsActivationCommitted || journal.Stage == windowsActivationRolledBack {
		return journal, nil
	}
	if journal.Stage == windowsActivationRollbackReady {
		return completeWindowsRollback(ctx, backend, journal, errors.New("interrupted rollback recovered"))
	}
	// Once a previous activator may have changed SCM, recovery always restores
	// the old exact commands first. It never guesses which candidate process
	// survived a power loss.
	if journal.Stage != windowsActivationStaged {
		return rollbackWindowsActivation(ctx, backend, journal, errors.New("interrupted activation recovered"))
	}
	journal.Stage = windowsActivationSwitching
	if err = backend.WriteJournal(journal); err != nil {
		return journal, err
	}
	if err = backend.StopServices(ctx); err != nil {
		return rollbackWindowsActivation(ctx, backend, journal, err)
	}
	if err = backend.ActivateBinary(ctx, journal); err != nil {
		return rollbackWindowsActivation(ctx, backend, journal, err)
	}
	if err = backend.SetServiceTargets(ctx, journal.NewHostd, journal.NewUpdater, journal.NewSSH); err != nil {
		return rollbackWindowsActivation(ctx, backend, journal, err)
	}
	if err = backend.StartServices(ctx, true, true, journal.NewSSH.WasRunning); err != nil {
		return rollbackWindowsActivation(ctx, backend, journal, err)
	}
	journal.Stage = windowsActivationServicesLive
	if err = backend.WriteJournal(journal); err != nil {
		return rollbackWindowsActivation(ctx, backend, journal, err)
	}
	if err = backend.VerifyHealth(ctx, journal); err != nil {
		return rollbackWindowsActivation(ctx, backend, journal, err)
	}
	if err = backend.CommitCLI(ctx, journal); err != nil {
		return rollbackWindowsActivation(ctx, backend, journal, err)
	}
	journal.Stage, journal.Failure = windowsActivationCommitted, ""
	if err = backend.WriteJournal(journal); err != nil {
		// CLI publication is the final atomic commit. Failure to record that fact
		// must still restore both services and the previous CLI pointer.
		return rollbackWindowsActivation(ctx, backend, journal, err)
	}
	return journal, nil
}

func rollbackWindowsActivation(ctx context.Context, backend windowsActivationBackend, journal windowsActivationJournal, cause error) (windowsActivationJournal, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	journal.Stage, journal.Failure = windowsActivationRollingBack, boundedWindowsActivationFailure(cause)
	journalErr := backend.WriteJournal(journal)
	stopErr := backend.StopServices(ctx)
	var targetErr error
	var binaryErr error
	if stopErr == nil {
		binaryErr = backend.RestoreBinary(ctx, journal)
	}
	if stopErr == nil && binaryErr == nil {
		targetErr = backend.SetServiceTargets(ctx, journal.OldHostd, journal.OldUpdater, journal.OldSSH)
	}
	// Restore the durable version and CLI pointer before restarting the old
	// updater. Otherwise the old updater can observe candidate state and race
	// this rollback.
	cliErr := backend.CommitCLI(ctx, windowsActivationJournal{Version: journal.PreviousVersion, PreviousCLIRecord: journal.NewCLIRecord, NewCLIRecord: journal.PreviousCLIRecord})
	quarantineErr := backend.Quarantine(ctx, journal)
	rollbackErr := errors.Join(journalErr, stopErr, binaryErr, targetErr, cliErr, quarantineErr)
	if rollbackErr != nil {
		return journal, errors.Join(cause, rollbackErr)
	}
	// Persist that every mutable pointer is old before starting the old updater.
	// Recovery from this cut point may only finish rollback.
	journal.Stage = windowsActivationRollbackReady
	if err := backend.WriteJournal(journal); err != nil {
		return journal, errors.Join(cause, err)
	}
	return completeWindowsRollback(ctx, backend, journal, cause)
}

func completeWindowsRollback(_ context.Context, backend windowsActivationBackend, journal windowsActivationJournal, cause error) (windowsActivationJournal, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if journal.Stage != windowsActivationRollbackReady {
		return journal, errors.Join(cause, errInvalidWindowsActivation)
	}
	if err := backend.StartServices(ctx, journal.OldHostd.WasRunning, journal.OldUpdater.WasRunning, journal.OldSSH.WasRunning); err != nil {
		return journal, errors.Join(cause, err)
	}
	journal.Stage = windowsActivationRolledBack
	if err := backend.WriteJournal(journal); err != nil {
		return journal, errors.Join(cause, err)
	}
	return journal, cause
}

func validWindowsActivationJournal(j windowsActivationJournal) bool {
	if j.Schema != windowsActivationJournalSchema || len(j.TransactionID) != 32 || !lowerHex(j.TransactionID) || !exactReleasePattern.MatchString(j.Version) || !exactReleasePattern.MatchString(j.PreviousVersion) || !validWindowsActivationStage(j.Stage) || j.Architecture != "amd64" && j.Architecture != "arm64" || len(j.Failure) > 4096 {
		return false
	}
	for _, component := range []windowsActivationComponent{j.Runtime, j.CLI, j.Hostd, j.Updater, j.PreviousBinary} {
		if component.Path == "" || len(component.SHA256) != 64 || !lowerHex(component.SHA256) || component.Length <= 0 || component.Length > maxWindowsComponentSize {
			return false
		}
	}
	for _, target := range []windowsServiceTarget{j.OldHostd, j.NewHostd} {
		if target.Executable == "" || len(target.Arguments) != 1 || target.Arguments[0] != "__runtime-hostd" {
			return false
		}
	}
	for _, target := range []windowsServiceTarget{j.OldUpdater, j.NewUpdater} {
		if target.Executable == "" || len(target.Arguments) != 1 || target.Arguments[0] != "__runtime-updated" {
			return false
		}
	}
	if (j.OldSSH.Executable == "") != (j.NewSSH.Executable == "") || j.OldSSH.Executable != "" && (!validWindowsSSHArguments(j.OldSSH.Arguments) || !validWindowsSSHArguments(j.NewSSH.Arguments)) {
		return false
	}
	// The stable layout.Binary path is the sole CLI/runtime entry point. These
	// fields remain in the journal for decoding old schema-shaped records, but a
	// new transaction must never create or consume a pb.active pointer.
	return j.PreviousCLIRecord == "" && j.NewCLIRecord == ""
}

func validWindowsSSHArguments(arguments []string) bool {
	return len(arguments) == 5 && arguments[0] == "__windows-sshd-service" && arguments[1] == "--sshd" && strings.EqualFold(arguments[2], `C:\Program Files\OpenSSH\sshd.exe`) && arguments[3] == "--config" && strings.EqualFold(arguments[4], `C:\ProgramData\Paperboat\ssh\sshd_config`)
}

func boundedWindowsActivationFailure(cause error) string {
	if cause == nil {
		return "activation failed"
	}
	const maximum = 2048
	message := strings.Map(func(character rune) rune {
		if character == '\x00' || character == '\r' || character == '\n' {
			return ' '
		}
		return character
	}, cause.Error())
	if len(message) > maximum {
		message = message[:maximum]
	}
	return message
}

func validWindowsActivationStage(stage windowsActivationStage) bool {
	switch stage {
	case windowsActivationStaged, windowsActivationSwitching, windowsActivationServicesLive, windowsActivationCommitted, windowsActivationRollingBack, windowsActivationRollbackReady, windowsActivationRolledBack:
		return true
	default:
		return false
	}
}

func lowerHex(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func windowsActivationServiceNames(setupMode string) []string {
	if setupMode == "host" {
		return []string{"PaperboatSshd", "PaperboatHostd", "PaperboatUpdated"}
	}
	return []string{"PaperboatHostd", "PaperboatUpdated"}
}

func validWindowsSSHRoleTarget(setupMode string, target windowsServiceTarget) bool {
	return setupMode == "host" && target.Executable != "" || setupMode == "client" && target.Executable == ""
}

func windowsActivationBlocksVersion(journal windowsActivationJournal, version string) bool {
	return journal.Stage != windowsActivationCommitted && journal.Stage != windowsActivationRolledBack && (journal.Version == version || journal.PreviousVersion == version)
}
