//go:build darwin || linux

package hostservice

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
)

type fakeUpdateFetcher struct{ body []byte }

func (f fakeUpdateFetcher) Fetch(_ context.Context, _ bootstrap.ArtifactTarget, directory string) (string, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(directory, ".paperboat-artifact-")
	if err != nil {
		return "", err
	}
	if err := file.Chmod(0o700); err != nil {
		file.Close()
		return "", err
	}
	_, err = file.Write(f.body)
	return file.Name(), errors.Join(err, file.Close())
}

type fakeUpdateServices struct{ workerRestarts, hostRestarts int }

func (s *fakeUpdateServices) RestartWorker(context.Context) error { s.workerRestarts++; return nil }
func (s *fakeUpdateServices) RestartHost()                        { s.hostRestarts++ }

type fakeUpdateHealth struct{ err error }

func (h fakeUpdateHealth) Check(context.Context, string) error { return h.err }

func TestRootUpdateActivatesPBArtifactAndPreservesPrevious(t *testing.T) {
	manager, artifact := testUpdateManager(t, nil)
	version, err := manager.activate(context.Background(), artifact)
	if err != nil || version != "2026.07.27" {
		t.Fatalf("activate version=%q err=%v", version, err)
	}
	assertFileBody(t, manager.config.BinaryPath, string(testBinary("new")))
	if info, err := os.Stat(manager.config.BinaryPath); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("installed mode=%v err=%v", info.Mode().Perm(), err)
	}
	assertFileBody(t, manager.config.BinaryPath+".previous", string(testBinary("old")))
	services := manager.services.(*fakeUpdateServices)
	if services.workerRestarts != 1 || services.hostRestarts != 1 {
		t.Fatalf("restarts=%+v", services)
	}
	entry, err := manager.loadJournal()
	if err != nil || entry.Stage != "committed" || entry.Version != version {
		t.Fatalf("journal=%+v err=%v", entry, err)
	}
	if replayed, err := manager.activate(context.Background(), artifact); err != nil || replayed != version || services.workerRestarts != 1 || services.hostRestarts != 1 {
		t.Fatalf("replay version=%q err=%v restarts=%+v", replayed, err, services)
	}
	if health := manager.UpdateHealth(); health != "healthy" {
		t.Fatalf("update health=%q", health)
	}
}

func TestRootUpdateHealthFailureRollsBackPB(t *testing.T) {
	manager, artifact := testUpdateManager(t, errors.New("new runtime unhealthy"))
	if _, err := manager.activate(context.Background(), artifact); err == nil {
		t.Fatal("health failure was accepted")
	}
	assertFileBody(t, manager.config.BinaryPath, string(testBinary("old")))
	if _, err := os.Stat(manager.journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal error=%v", err)
	}
	if count := manager.RollbackCount(); count != 1 {
		t.Fatalf("rollback count=%d", count)
	}
	if health := manager.UpdateHealth(); health != "healthy" {
		t.Fatalf("recovered rollback health=%q", health)
	}
}

func TestRootUpdateRejectsSignedBinaryForDifferentTarget(t *testing.T) {
	manager, _ := testUpdateManager(t, nil)
	foreign := make([]byte, 32)
	if runtime.GOOS == "linux" {
		binary.LittleEndian.PutUint32(foreign[:4], 0xfeedfacf)
		binary.LittleEndian.PutUint32(foreign[4:8], 0x0100000c)
	} else {
		copy(foreign, "\x7fELF")
		foreign[4], foreign[5] = 2, 1
		binary.LittleEndian.PutUint16(foreign[18:20], 62)
	}
	artifact, _ := signedUpdate(t, foreign)
	manager.fetcher = fakeUpdateFetcher{body: foreign}
	if _, err := manager.activate(context.Background(), artifact); !errors.Is(err, ErrUpdateInvalid) {
		t.Fatalf("foreign binary error=%v", err)
	}
	assertFileBody(t, manager.config.BinaryPath, string(testBinary("old")))
}

func TestRootUpdateRecoveryRollsBackInterruptedActivation(t *testing.T) {
	manager, _ := testUpdateManager(t, nil)
	if err := os.Rename(manager.config.BinaryPath, manager.config.BinaryPath+".rollback"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manager.config.BinaryPath, testBinary("new"), 0o700); err != nil {
		t.Fatal(err)
	}
	entry := updateJournal{Schema: updateJournalSchemaV1, Stage: "checking", Version: "2026.07.27", PreviousVersion: "2026.07.26", UpdatedAt: time.Now().UTC()}
	if err := manager.writeJournal(entry); err != nil {
		t.Fatal(err)
	}
	if err := manager.recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertFileBody(t, manager.config.BinaryPath, string(testBinary("old")))
	if count := manager.RollbackCount(); count != 1 {
		t.Fatalf("recovery rollback count=%d", count)
	}
	if restarts := manager.services.(*fakeUpdateServices).workerRestarts; restarts != 0 {
		t.Fatalf("constructor recovery restarted worker %d times", restarts)
	}
	body, err := os.ReadFile(manager.current)
	if err != nil || !strings.Contains(string(body), `"version":"2026.07.26"`) {
		t.Fatalf("rollback current metadata=%q err=%v", body, err)
	}
}

func TestRootUpdateRecoveryDiscardsStagedTransactionWithoutRollback(t *testing.T) {
	manager, _ := testUpdateManager(t, nil)
	staged, err := os.CreateTemp(filepath.Dir(manager.config.BinaryPath), ".paperboat-artifact-")
	if err != nil {
		t.Fatal(err)
	}
	stagedPath := staged.Name()
	if err := staged.Close(); err != nil {
		t.Fatal(err)
	}
	entry := updateJournal{Schema: updateJournalSchemaV1, Stage: "staged", Version: "2026.07.27", PreviousVersion: "2026.07.26", Staged: stagedPath, UpdatedAt: time.Now().UTC()}
	if err := manager.writeJournal(entry); err != nil {
		t.Fatal(err)
	}
	if err := manager.recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertFileBody(t, manager.config.BinaryPath, string(testBinary("old")))
	if _, err := os.Stat(stagedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged artifact remains: %v", err)
	}
	if count := manager.RollbackCount(); count != 0 {
		t.Fatalf("staged recovery rollback count=%d", count)
	}
}

func TestRootUpdateLiveHealthFailureStillRestartsWorkerAfterRollback(t *testing.T) {
	manager, artifact := testUpdateManager(t, errors.New("new runtime unhealthy"))
	if _, err := manager.activate(context.Background(), artifact); err == nil {
		t.Fatal("health failure was accepted")
	}
	if restarts := manager.services.(*fakeUpdateServices).workerRestarts; restarts != 2 {
		t.Fatalf("live activation worker restarts=%d, want activation and rollback", restarts)
	}
}

func TestUpdateValidationReportsExactFailedInvariant(t *testing.T) {
	manager, _ := testUpdateManager(t, nil)
	manager.config.CurrentVersion = "invalid"
	err := manager.validate()
	if !errors.Is(err, ErrUpdateInvalid) || !strings.Contains(err.Error(), `current version "invalid" is invalid`) {
		t.Fatalf("validation error=%v", err)
	}
}

func TestRootUpdateStateCanLiveUnderUserOwnedParent(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "shared")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	updateRoot := filepath.Join(parent, "privileged-updates")
	if err := os.Mkdir(updateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	manager, _ := testUpdateManager(t, nil)
	manager.config.StateRoot = updateRoot
	manager.journal = filepath.Join(updateRoot, "update-journal.json")
	manager.current = filepath.Join(updateRoot, "update-current.json")
	manager.rollbacks = filepath.Join(updateRoot, "update-rollbacks.json")
	if err := manager.validate(); err != nil {
		t.Fatalf("dedicated update root rejected: %v", err)
	}
}

func TestRootUpdateRecoveryDoesNotProbeCommittedActivationBeforeListenerStarts(t *testing.T) {
	manager, _ := testUpdateManager(t, errors.New("listener is not started"))
	entry := updateJournal{Schema: updateJournalSchemaV1, Stage: "committed", Version: "2026.07.27", PreviousVersion: "2026.07.26", UpdatedAt: time.Now().UTC()}
	manager.config.CurrentVersion = entry.Version
	if err := manager.writeJournal(entry); err != nil {
		t.Fatal(err)
	}
	if err := manager.recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if count := manager.RollbackCount(); count != 0 {
		t.Fatalf("committed recovery rollback count=%d", count)
	}
}

func TestRootUpdateRecoveryReconcilesCommittedJournalAfterRootReplacement(t *testing.T) {
	manager, _ := testUpdateManager(t, errors.New("listener is not started"))
	entry := updateJournal{Schema: updateJournalSchemaV1, Stage: "committed", Version: "2026.07.27", PreviousVersion: "2026.07.26", UpdatedAt: time.Now().UTC()}
	manager.config.CurrentVersion = "2026.07.28"
	if err := manager.writeJournal(entry); err != nil {
		t.Fatal(err)
	}
	if err := manager.recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(manager.journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale committed journal remains: %v", err)
	}
	if count := manager.RollbackCount(); count != 0 {
		t.Fatalf("root replacement rollback count=%d", count)
	}
	body, err := os.ReadFile(manager.current)
	if err != nil || !strings.Contains(string(body), manager.config.CurrentVersion) {
		t.Fatalf("current version body=%q error=%v", body, err)
	}
}

func TestRootUpdateHealthFailsClosedForRepeatedOrInvalidRecoveryState(t *testing.T) {
	manager, _ := testUpdateManager(t, nil)
	if err := manager.incrementRollbackCount(); err != nil {
		t.Fatal(err)
	}
	if err := manager.incrementRollbackCount(); err != nil {
		t.Fatal(err)
	}
	if health := manager.UpdateHealth(); health != "recovery_required" {
		t.Fatalf("repeated rollback health=%q", health)
	}
	if err := os.Remove(manager.rollbacks); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manager.journal, []byte(`{"schema":"paperboat.host-update/v1","stage":"checking"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if health := manager.UpdateHealth(); health != "recovery_required" {
		t.Fatalf("invalid journal health=%q", health)
	}
}

func TestReleaseVersionComparisonIncludesRevision(t *testing.T) {
	for _, version := range []string{"2026.07.25", "2026.07.25.4"} {
		if !validReleaseVersion(version) {
			t.Fatalf("valid version rejected: %s", version)
		}
	}
	for _, version := range []string{"2026.07", "2026.07.25.4.1", "2026.07.x"} {
		if validReleaseVersion(version) {
			t.Fatalf("invalid version accepted: %s", version)
		}
	}
}

func testUpdateManager(t *testing.T, healthErr error) (*UpdateManager, bootstrap.ArtifactTarget) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	install, state := filepath.Join(root, "install"), filepath.Join(root, "state")
	for _, directory := range []string{install, state} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	binaryPath := filepath.Join(install, "pb")
	if err := os.WriteFile(binaryPath, testBinary("old"), 0o700); err != nil {
		t.Fatal(err)
	}
	newBody := testBinary("new")
	artifact, _ := signedUpdate(t, newBody)
	manager := &UpdateManager{
		config:   UpdateConfig{StateRoot: state, BinaryPath: binaryPath, CurrentVersion: "2026.07.26", ListenAddress: "127.0.0.1:8080"},
		ownerUID: os.Getuid(), fetcher: fakeUpdateFetcher{body: newBody}, services: &fakeUpdateServices{}, health: fakeUpdateHealth{err: healthErr},
		journal: filepath.Join(state, "update-journal.json"), current: filepath.Join(state, "update-current.json"), rollbacks: filepath.Join(state, "update-rollbacks.json"),
	}
	if err := manager.validate(); err != nil {
		t.Fatal(err)
	}
	return manager, artifact
}

func testBinary(label string) []byte {
	header := make([]byte, 32)
	if runtime.GOOS == "linux" {
		copy(header, "\x7fELF")
		header[4], header[5] = 2, 1
		machine := uint16(62)
		if runtime.GOARCH == "arm64" {
			machine = 183
		}
		binary.LittleEndian.PutUint16(header[18:20], machine)
	} else {
		binary.LittleEndian.PutUint32(header[:4], 0xfeedfacf)
		cpu := uint32(0x01000007)
		if runtime.GOARCH == "arm64" {
			cpu = 0x0100000c
		}
		binary.LittleEndian.PutUint32(header[4:8], cpu)
	}
	return append(header, label...)
}

func signedUpdate(t *testing.T, body []byte) (bootstrap.ArtifactTarget, string) {
	t.Helper()
	_ = body
	manifest := bootstrap.ArtifactTarget{Schema: bootstrap.ArtifactTargetSchemaV1, Kind: bootstrap.ArtifactKindPB, Version: "2026.07.27", Platform: runtime.GOOS, Architecture: runtime.GOARCH, RepositoryURL: "https://updates.example.test/paperboat", TargetPath: "pb-" + runtime.GOOS + "-" + runtime.GOARCH}
	return manifest, ""
}

func assertFileBody(t *testing.T, path, expected string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil || string(body) != expected {
		t.Fatalf("%s body=%q err=%v", path, body, err)
	}
}
