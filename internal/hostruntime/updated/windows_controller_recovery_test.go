//go:build windows

package updated

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestWindowsControllerReclaimsStaleRollbackReady(t *testing.T) {
	journal := testWindowsActivationJournal()
	journal.Stage = windowsActivationRollbackReady
	rolledBack := journal
	rolledBack.Stage = windowsActivationRolledBack

	oldLoad := loadWindowsActivationJournalForController
	oldResume := resumeWindowsActivationForController
	t.Cleanup(func() {
		loadWindowsActivationJournalForController = oldLoad
		resumeWindowsActivationForController = oldResume
	})

	loads := 0
	loadWindowsActivationJournalForController = func(WindowsConfig) (windowsActivationJournal, error) {
		loads++
		if loads == 1 {
			return journal, nil
		}
		return rolledBack, nil
	}
	resumed := 0
	resumeWindowsActivationForController = func(context.Context, WindowsConfig) (bool, error) {
		resumed++
		return true, nil
	}

	controller := &windowsController{activeVersion: journal.PreviousVersion}
	blocked, err := controller.activationBlockedContext(context.Background())
	if err != nil || blocked {
		t.Fatalf("blocked=%t err=%v, want recovered rollback", blocked, err)
	}
	if resumed != 1 || loads != 2 {
		t.Fatalf("recovery calls=%d journal loads=%d, want one recovery and a terminal reread", resumed, loads)
	}
}

func TestWindowsControllerKeepsRollbackReadyFencedWhenRecoveryFails(t *testing.T) {
	journal := testWindowsActivationJournal()
	journal.Stage = windowsActivationRollbackReady
	cause := errors.New("activator start failed")

	oldLoad := loadWindowsActivationJournalForController
	oldResume := resumeWindowsActivationForController
	t.Cleanup(func() {
		loadWindowsActivationJournalForController = oldLoad
		resumeWindowsActivationForController = oldResume
	})
	loadWindowsActivationJournalForController = func(WindowsConfig) (windowsActivationJournal, error) {
		return journal, nil
	}
	resumeWindowsActivationForController = func(context.Context, WindowsConfig) (bool, error) {
		return false, cause
	}

	controller := &windowsController{activeVersion: journal.PreviousVersion}
	blocked, err := controller.activationBlockedContext(context.Background())
	if !blocked || !errors.Is(err, ErrWindowsActivationUnavailable) || !errors.Is(err, cause) {
		t.Fatalf("blocked=%t err=%v, want typed unavailable recovery error", blocked, err)
	}
}

func TestWindowsControllerSerializesStaleRollbackRecovery(t *testing.T) {
	journal := testWindowsActivationJournal()
	journal.Stage = windowsActivationRollbackReady

	oldLoad := loadWindowsActivationJournalForController
	oldResume := resumeWindowsActivationForController
	t.Cleanup(func() {
		loadWindowsActivationJournalForController = oldLoad
		resumeWindowsActivationForController = oldResume
	})
	loadWindowsActivationJournalForController = func(WindowsConfig) (windowsActivationJournal, error) {
		return journal, nil
	}

	var mu sync.Mutex
	active, maximum, calls := 0, 0, 0
	resumeWindowsActivationForController = func(context.Context, WindowsConfig) (bool, error) {
		mu.Lock()
		active++
		calls++
		if active > maximum {
			maximum = active
		}
		mu.Unlock()
		// The controller lock, rather than the recovery implementation, must
		// prevent duplicate handoffs from concurrent control requests.
		mu.Lock()
		active--
		mu.Unlock()
		return false, nil
	}

	controller := &windowsController{activeVersion: journal.PreviousVersion}
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _ = controller.activationBlockedContext(context.Background())
		}()
	}
	wait.Wait()
	if calls != 2 || maximum != 1 {
		t.Fatalf("recovery calls=%d max concurrency=%d, want two serialized calls", calls, maximum)
	}
}

func TestWindowsControllerRecoveryOnlyTargetsStaleRollbackReady(t *testing.T) {
	j := testWindowsActivationJournal()
	for _, test := range []struct {
		name          string
		stage         windowsActivationStage
		activeVersion string
		want          bool
	}{
		{name: "rollback_ready_previous", stage: windowsActivationRollbackReady, activeVersion: j.PreviousVersion, want: true},
		{name: "rollback_ready_candidate", stage: windowsActivationRollbackReady, activeVersion: j.Version, want: false},
		{name: "switching_previous", stage: windowsActivationSwitching, activeVersion: j.PreviousVersion, want: false},
		{name: "rolled_back_previous", stage: windowsActivationRolledBack, activeVersion: j.PreviousVersion, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			j.Stage = test.stage
			if got := windowsActivationNeedsControllerRecovery(j, test.activeVersion); got != test.want {
				t.Fatalf("needs recovery=%t, want %t", got, test.want)
			}
		})
	}
}
