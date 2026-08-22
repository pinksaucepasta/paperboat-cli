//go:build windows

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/adrg/xdg"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/localdaemon"
)

func TestRemovePlatformProductInstallationHandsOffEveryRegisteredMSI(t *testing.T) {
	previousEnumerate := enumeratePaperboatMSIProducts
	previousRun := runPaperboatMSIUninstall
	t.Cleanup(func() {
		enumeratePaperboatMSIProducts = previousEnumerate
		runPaperboatMSIUninstall = previousRun
	})
	first := "{11111111-1111-1111-1111-111111111111}"
	second := "{22222222-2222-2222-2222-222222222222}"
	enumeratePaperboatMSIProducts = func() ([]string, error) { return []string{first, second}, nil }
	var calls []string
	runPaperboatMSIUninstall = func(_ context.Context, productCode string) error {
		calls = append(calls, productCode)
		if productCode == first {
			return errors.New("first MSI failed")
		}
		return nil
	}
	err := removeRegisteredPaperboatMSIProducts(context.Background())
	if got, want := strings.Join(calls, ","), first+","+second; got != want {
		t.Fatalf("MSI uninstall calls = %q, want %q", got, want)
	}
	if err == nil || !strings.Contains(err.Error(), "first MSI failed") {
		t.Fatalf("MSI uninstall error = %v", err)
	}
}

func TestWindowsRegisteredCleanupUninstallsMSIBeforeRuntimePurge(t *testing.T) {
	previousEnumerate := enumeratePaperboatMSIProducts
	previousRun := runPaperboatMSIUninstall
	previousGlobal := runWindowsGlobalCleanup
	previousPurge := purgeWindowsHostRuntime
	t.Cleanup(func() {
		enumeratePaperboatMSIProducts = previousEnumerate
		runPaperboatMSIUninstall = previousRun
		runWindowsGlobalCleanup = previousGlobal
		purgeWindowsHostRuntime = previousPurge
	})
	product := "{11111111-1111-1111-1111-111111111111}"
	enumeratePaperboatMSIProducts = func() ([]string, error) { return []string{product}, nil }
	var calls []string
	globalFailure := errors.New("global cleanup failed")
	runWindowsGlobalCleanup = func(context.Context) error {
		calls = append(calls, "global")
		return globalFailure
	}
	runPaperboatMSIUninstall = func(context.Context, string) error {
		calls = append(calls, "msi")
		return nil
	}
	purgeWindowsHostRuntime = func(context.Context) error {
		calls = append(calls, "runtime")
		return nil
	}
	if err := performWindowsRegisteredCleanup(context.Background()); !errors.Is(err, globalFailure) {
		t.Fatalf("registered cleanup error = %v", err)
	}
	if got := strings.Join(calls, ","); got != "global,msi,runtime" {
		t.Fatalf("registered cleanup order = %q, want global,msi,runtime", got)
	}
	calls = nil
	runWindowsGlobalCleanup = func(context.Context) error {
		calls = append(calls, "global")
		return nil
	}
	enumeratePaperboatMSIProducts = func() ([]string, error) { return nil, nil }
	if err := performWindowsRegisteredCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls, ","); got != "global,runtime" {
		t.Fatalf("standalone cleanup order = %q, want global,runtime", got)
	}
}

func TestWindowsUninstallPlanIsProtectedBoundedAndHelperIsNonRecursive(t *testing.T) {
	directory := t.TempDir()
	previousExecutable := windowsUninstallExecutable
	windowsUninstallExecutable = func() (string, error) { return filepath.Join(directory, "paperboat-uninstall-helper.exe"), nil }
	t.Cleanup(func() { windowsUninstallExecutable = previousExecutable })
	if err := protectWindowsUninstallPath(directory, true); err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(directory, "plan.json")
	statusPath := filepath.Join(directory, "status.json")
	now := time.Now().UTC()
	plan := windowsUninstallPlan{
		Schema: windowsUninstallPlanSchema, ProcessIDs: []uint32{uint32(os.Getpid()) + 100000},
		StatusPath: statusPath, InboxPaths: []string{filepath.Join(directory, "Paperboat Inbox")},
		CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	if err := writeProtectedWindowsUninstallJSON(planPath, plan); err != nil {
		t.Fatal(err)
	}
	loaded, err := readWindowsUninstallPlan(planPath)
	if err != nil || loaded.Schema != windowsUninstallPlanSchema || loaded.StatusPath != statusPath {
		t.Fatalf("loaded plan=%+v error=%v", loaded, err)
	}
	windowsUninstallExecutable = func() (string, error) {
		return filepath.Join(directory, "other", "paperboat-uninstall-helper.exe"), nil
	}
	if _, err := readWindowsUninstallPlan(planPath); err == nil {
		t.Fatal("plan outside the running helper directory was accepted")
	}
	windowsUninstallExecutable = func() (string, error) { return filepath.Join(directory, "paperboat-uninstall-helper.exe"), nil }
	plan.CreatedAt = now.Add(-6 * time.Minute)
	plan.ExpiresAt = now.Add(-time.Minute)
	if err := writeProtectedWindowsUninstallJSON(planPath, plan); err != nil {
		t.Fatal(err)
	}
	if _, err := readWindowsUninstallPlan(planPath); err == nil {
		t.Fatal("expired uninstall plan was accepted")
	}
	command := platformUninstallHelperCommand()
	if command.Name() != "__complete-uninstall" || !command.Hidden || strings.Contains(command.Use, "pb uninstall") || command.Flags().Lookup("plan") == nil {
		t.Fatalf("unsafe or recursive helper command: use=%q hidden=%v", command.Use, command.Hidden)
	}
	message := platformUninstallSuccessMessage()
	if !strings.Contains(message, "cleanup was started") || strings.Contains(strings.ToLower(message), "completely removed") {
		t.Fatalf("Windows uninstall status is not honest about asynchronous completion: %q", message)
	}
}

func TestWindowsUninstallHandoffAcceptsOnlyReadyProtectedStatus(t *testing.T) {
	directory := t.TempDir()
	if err := protectWindowsUninstallPath(directory, true); err != nil {
		t.Fatal(err)
	}
	statusPath := filepath.Join(directory, "status.json")
	if err := writeProtectedWindowsUninstallJSON(statusPath, windowsUninstallStatus{Schema: windowsUninstallStatusSchema, State: "waiting_for_parent", UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitForWindowsUninstallHandoff(ctx, statusPath); err != nil {
		t.Fatalf("ready protected handoff was rejected: %v", err)
	}
	if err := writeProtectedWindowsUninstallJSON(statusPath, windowsUninstallStatus{Schema: windowsUninstallStatusSchema, State: "failed", Error: "preview cleanup failed", UpdatedAt: time.Now().UTC(), CompletedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := waitForWindowsUninstallHandoff(ctx, statusPath); err == nil || !strings.Contains(err.Error(), "preview cleanup failed") {
		t.Fatalf("failed handoff status = %v", err)
	}
}

func TestWindowsUninstallDefersPreviewCleanupToElevatedHandoff(t *testing.T) {
	if err := cleanupUninstallDurablePreviewServices(nil); err != nil {
		t.Fatalf("Windows uninstall called the user preview broker before handoff: %v", err)
	}
}

func TestWindowsUninstallRequiresConfirmedDaemonStopBeforeProductRemoval(t *testing.T) {
	if !platformRequiresConfirmedDaemonStop() {
		t.Fatal("Windows uninstall may remove product/state after uncertain daemon termination")
	}
}

func TestCopyWindowsUninstallHelperVerifiesExactBytes(t *testing.T) {
	directory := t.TempDir()
	if err := protectWindowsUninstallPath(directory, true); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "source.exe")
	want := []byte("paperboat helper test bytes")
	if err := os.WriteFile(source, want, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "helper.exe")
	if err := copyWindowsUninstallHelper(source, destination); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("copied helper bytes=%q error=%v", got, err)
	}
}

func TestRemovePathPreservingIsCaseInsensitiveOnWindows(t *testing.T) {
	root := t.TempDir()
	inboxPath := filepath.Join(root, "Nested", "Paperboat Inbox")
	if err := os.MkdirAll(inboxPath, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(inboxPath, "Keep.txt")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "remove.txt"), []byte("remove"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removePathPreserving(strings.ToUpper(root), []string{strings.ToLower(inboxPath)}); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(sentinel); err != nil || string(content) != "keep" {
		t.Fatalf("case-insensitive Inbox preservation content=%q error=%v", content, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "remove.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("non-Inbox state remains: %v", err)
	}
}

func TestFilesystemRootRejectsWindowsDriveAndUNCShare(t *testing.T) {
	if !filesystemRoot(`C:\`) || !filesystemRoot(`\\server\share\`) || filesystemRoot(`C:\Paperboat`) {
		t.Fatal("Windows filesystem-root detection accepted a destructive cleanup target")
	}
}

type fakeMSIExitError struct{ code int }

func (e fakeMSIExitError) Error() string { return "MSI exit " + strconv.Itoa(e.code) }
func (e fakeMSIExitError) ExitCode() int { return e.code }

func TestMSIUninstallExitContractAcceptsOnlySuccessAndRebootRequired(t *testing.T) {
	if !successfulMSIUninstallExit(nil) || !successfulMSIUninstallExit(fakeMSIExitError{code: 3010}) || successfulMSIUninstallExit(fakeMSIExitError{code: 1603}) {
		t.Fatal("MSI uninstall exit contract did not distinguish success, reboot-required, and failure")
	}
}

var commandRuntimeTestSequence uint64

func commandLocalAPIServerConfig(path string, source localapi.SnapshotSource) (localapi.ServerConfig, error) {
	sid, err := localdaemon.CurrentUserSID()
	if err != nil {
		return localapi.ServerConfig{}, err
	}
	return localapi.ServerConfig{SocketPath: path, OwnerUID: -1, OwnerGID: -1, OwnerSID: sid, Source: source}, nil
}

func commandRuntimeTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	sequence := atomic.AddUint64(&commandRuntimeTestSequence, 1)
	stateRoot := filepath.Join(root, "state")
	runtimeRoot := filepath.Join(root, "runtime")
	socketPath := `\\.\pipe\paperboat-test-` + strconv.FormatUint(sequence, 10)
	previousPaths := currentLocalDaemonPaths
	currentLocalDaemonPaths = func() (localapi.Paths, error) {
		return localapi.Paths{
			StateRoot: stateRoot, RuntimeRoot: runtimeRoot, SocketPath: socketPath,
			LockPath: filepath.Join(stateRoot, "daemon.lock"),
		}, nil
	}
	t.Cleanup(func() { currentLocalDaemonPaths = previousPaths })
	t.Setenv("LOCALAPPDATA", root)
	t.Setenv("APPDATA", root)
	previous := []string{xdg.Home, xdg.ConfigHome, xdg.CacheHome, xdg.DataHome, xdg.StateHome, xdg.RuntimeDir}
	xdg.Home = root
	xdg.ConfigHome = root
	xdg.CacheHome = root
	xdg.DataHome = root
	xdg.StateHome = root
	xdg.RuntimeDir = root
	t.Cleanup(func() {
		xdg.Home, xdg.ConfigHome, xdg.CacheHome, xdg.DataHome, xdg.StateHome, xdg.RuntimeDir = previous[0], previous[1], previous[2], previous[3], previous[4], previous[5]
	})
	return root
}

func isolateCommandCredentialLocation(t *testing.T, root string) {
	t.Helper()
	previous := xdg.ConfigHome
	xdg.ConfigHome = root
	t.Cleanup(func() { xdg.ConfigHome = previous })
}

func waitForCommandSocket(t *testing.T, path string) {
	t.Helper()
	client, err := localapi.NewClient(path, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_, err = client.Snapshot(ctx)
		cancel()
		if err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("local command pipe %s was not ready: %v", path, err)
}
