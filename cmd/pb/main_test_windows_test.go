//go:build windows

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/adrg/xdg"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/localdaemon"
	"golang.org/x/sys/windows"
)

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

func TestWindowsUninstallRequiresConfirmedDaemonStopBeforeProductRemoval(t *testing.T) {
	if !platformRequiresConfirmedDaemonStop() {
		t.Fatal("Windows uninstall may remove product/state after uncertain daemon termination")
	}
}

func TestWindowsUninstallSchedulesCompleteHelperDirectoryDeletion(t *testing.T) {
	previous := moveWindowsFileAtReboot
	var deleted []string
	moveWindowsFileAtReboot = func(path *uint16) error {
		deleted = append(deleted, windows.UTF16PtrToString(path))
		return nil
	}
	t.Cleanup(func() { moveWindowsFileAtReboot = previous })
	scheduleWindowsUninstallDirectoryDeletion(`C:\unrelated`)
	if len(deleted) != 0 {
		t.Fatalf("unsafe helper directory scheduled deletions: %v", deleted)
	}
	directory := filepath.Join(os.TempDir(), "Paperboat Uninstall", "0123456789abcdef0123456789abcdef")
	scheduleWindowsUninstallDirectoryDeletion(directory)
	want := []string{
		filepath.Join(directory, "plan.json"),
		filepath.Join(directory, "status.json"),
		filepath.Join(directory, "paperboat-uninstall-helper.exe"),
		directory,
	}
	if !reflect.DeepEqual(deleted, want) {
		t.Fatalf("scheduled helper deletions=%v want=%v", deleted, want)
	}
}

func TestRecoverExpiredWindowsUninstallHelpersRemovesOnlyValidatedInactiveRecords(t *testing.T) {
	previousRunning := windowsProcessIsRunning
	previousHelperRunning := windowsHelperIsRunning
	previousRoot := windowsUninstallRoot
	testRoot := filepath.Join(t.TempDir(), "Paperboat Uninstall")
	windowsUninstallRoot = func() string { return testRoot }
	windowsProcessIsRunning = func(processID uint32) (bool, error) {
		if processID != 4242 {
			t.Fatalf("unexpected process ID %d", processID)
		}
		return false, nil
	}
	windowsHelperIsRunning = func(string) (bool, error) { return false, nil }
	t.Cleanup(func() {
		windowsProcessIsRunning = previousRunning
		windowsHelperIsRunning = previousHelperRunning
		windowsUninstallRoot = previousRoot
	})
	root := windowsUninstallRoot()
	directory := filepath.Join(root, "0123456789abcdef0123456789abcdef")
	_ = os.RemoveAll(root)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := protectWindowsUninstallPath(directory, true); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-10 * time.Minute)
	statusPath := filepath.Join(directory, "status.json")
	plan := windowsUninstallPlan{Schema: windowsUninstallPlanSchema, ProcessIDs: []uint32{4242}, StatusPath: statusPath, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	if err := writeProtectedWindowsUninstallJSON(filepath.Join(directory, "plan.json"), plan); err != nil {
		t.Fatal(err)
	}
	if err := writeProtectedWindowsUninstallJSON(statusPath, windowsUninstallStatus{Schema: windowsUninstallStatusSchema, State: "failed", UpdatedAt: now, CompletedAt: now}); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(directory, "paperboat-uninstall-helper.exe")
	if err := os.WriteFile(helper, []byte("old helper"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := protectWindowsUninstallPath(helper, false); err != nil {
		t.Fatal(err)
	}
	if err := recoverExpiredWindowsUninstallHelpers(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired helper remains: %v", err)
	}
}

func TestRecoverExpiredWindowsUninstallHelpersRefusesActiveOrMalformedRecords(t *testing.T) {
	previousRunning := windowsProcessIsRunning
	previousHelperRunning := windowsHelperIsRunning
	previousRoot := windowsUninstallRoot
	testRoot := filepath.Join(t.TempDir(), "Paperboat Uninstall")
	windowsUninstallRoot = func() string { return testRoot }
	windowsHelperIsRunning = func(string) (bool, error) { return false, nil }
	t.Cleanup(func() {
		windowsProcessIsRunning = previousRunning
		windowsHelperIsRunning = previousHelperRunning
		windowsUninstallRoot = previousRoot
	})
	root := windowsUninstallRoot()
	_ = os.RemoveAll(root)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	directory := filepath.Join(root, "fedcba9876543210fedcba9876543210")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := protectWindowsUninstallPath(directory, true); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-10 * time.Minute)
	statusPath := filepath.Join(directory, "status.json")
	plan := windowsUninstallPlan{Schema: windowsUninstallPlanSchema, ProcessIDs: []uint32{4343}, StatusPath: statusPath, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	if err := writeProtectedWindowsUninstallJSON(filepath.Join(directory, "plan.json"), plan); err != nil {
		t.Fatal(err)
	}
	if err := writeProtectedWindowsUninstallJSON(statusPath, windowsUninstallStatus{Schema: windowsUninstallStatusSchema, State: "failed", UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(directory, "paperboat-uninstall-helper.exe")
	if err := os.WriteFile(helper, []byte("old helper"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := protectWindowsUninstallPath(helper, false); err != nil {
		t.Fatal(err)
	}
	windowsProcessIsRunning = func(uint32) (bool, error) { return true, nil }
	if err := recoverExpiredWindowsUninstallHelpers(); err == nil || !strings.Contains(err.Error(), "still active") {
		t.Fatalf("active helper recovery error = %v", err)
	}
	if _, err := os.Stat(directory); err != nil {
		t.Fatalf("active helper was removed: %v", err)
	}
	windowsProcessIsRunning = func(uint32) (bool, error) { return false, nil }
	if err := os.WriteFile(filepath.Join(directory, "unexpected"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverExpiredWindowsUninstallHelpers(); err == nil || !strings.Contains(err.Error(), "contents") {
		t.Fatalf("malformed helper recovery error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, "unexpected")); err != nil {
		t.Fatalf("malformed helper record was mutated: %v", err)
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
	// Named pipes are global on Windows. The process ID prevents a retry from
	// colliding with a pipe retained by an earlier test process, while the
	// sequence keeps roots distinct inside this process.
	socketPath := `\\.\pipe\paperboat-test-` + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatUint(sequence, 10)
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

func TestCommandRuntimeTestRootUsesProcessScopedNamedPipes(t *testing.T) {
	firstRoot := commandRuntimeTestRoot(t)
	first, err := currentLocalDaemonPaths()
	if err != nil {
		t.Fatal(err)
	}
	secondRoot := commandRuntimeTestRoot(t)
	second, err := currentLocalDaemonPaths()
	if err != nil {
		t.Fatal(err)
	}
	prefix := `\\.\pipe\paperboat-test-` + strconv.Itoa(os.Getpid()) + "-"
	if !strings.HasPrefix(first.SocketPath, prefix) || !strings.HasPrefix(second.SocketPath, prefix) {
		t.Fatalf("pipes must include the test process ID: first=%q second=%q", first.SocketPath, second.SocketPath)
	}
	if first.SocketPath == second.SocketPath || first.RuntimeRoot == second.RuntimeRoot || firstRoot == secondRoot {
		t.Fatalf("test roots must be distinct: first=%#v second=%#v", first, second)
	}
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
