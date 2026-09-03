//go:build windows

package updated

import (
	"context"
	"reflect"
	"testing"
)

// TestWindowsRollbackReadyOwnerLossIsRecoverableBeforeNextActivation models
// the updater/activator handoff around a durable rollback_ready journal. The
// updater may start while the one-shot activator still owns the transaction,
// but ownership is not a permanent lease: once the activator disappears the
// updater must resume the rollback, publish rolled_back, and unblock the
// next manual check/update operation.
func TestWindowsRollbackReadyOwnerLossIsRecoverableBeforeNextActivation(t *testing.T) {
	journal := testWindowsActivationJournal()
	journal.Stage = windowsActivationRollbackReady

	// Startup observes the activator still running and deliberately leaves the
	// journal alone. Manual operations remain fenced until recovery completes.
	if windowsActivationNeedsResume(journal, journal.PreviousVersion, true) {
		t.Fatal("updater attempted recovery while activator still owned transaction")
	}
	if !windowsActivationBlocksVersion(journal, journal.PreviousVersion) {
		t.Fatal("rollback_ready journal was not fenced while recovery was pending")
	}

	// The owner disappears after startup. A deterministic backend stands in for
	// the SCM and verifies the exact rollback choreography without touching a
	// Windows machine or service installation.
	if !windowsActivationNeedsResume(journal, journal.PreviousVersion, false) {
		t.Fatal("updater did not take ownership after activator disappeared")
	}
	backend := &recordingWindowsActivationBackend{}
	result, err := executeWindowsActivation(context.Background(), backend, journal)
	if err == nil || result.Stage != windowsActivationRolledBack {
		t.Fatalf("rollback recovery result=%+v err=%v", result, err)
	}
	if want := []string{"start", "verifyRollback", "journal:rolled_back"}; !reflect.DeepEqual(backend.events, want) {
		t.Fatalf("rollback recovery events=%q, want=%q", backend.events, want)
	}
	if windowsActivationBlocksVersion(result, journal.PreviousVersion) {
		t.Fatal("terminal rolled_back journal still blocked manual operations")
	}
	if windowsActivationNeedsResume(result, journal.PreviousVersion, false) {
		t.Fatal("terminal rolled_back journal still required recovery")
	}

	// A subsequent staged release is not poisoned by the recovered journal.
	next := testWindowsActivationJournal()
	next.PreviousVersion = journal.PreviousVersion
	next.Version = "2026.08.24.1"
	if !windowsActivationBlocksVersion(next, next.PreviousVersion) || !windowsActivationBlocksVersion(next, next.Version) {
		t.Fatal("new staged activation did not independently fence its active and candidate versions")
	}
}
