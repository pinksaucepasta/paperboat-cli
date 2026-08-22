//go:build windows

package localdaemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

type fakeWindowsDaemonProcess struct {
	identity     windowsDaemonProcessIdentity
	identityErr  error
	terminateErr error
	terminated   bool
	deadline     time.Time
}

func (p *fakeWindowsDaemonProcess) Identity() (windowsDaemonProcessIdentity, error) {
	return p.identity, p.identityErr
}

func (p *fakeWindowsDaemonProcess) TerminateAndWait(ctx context.Context) error {
	p.terminated = true
	p.deadline, _ = ctx.Deadline()
	return p.terminateErr
}

func (*fakeWindowsDaemonProcess) Close() error { return nil }

func TestInstallWindowsCurrentUserServiceStartsDetachedUserDaemon(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "pb.exe")
	if err := os.WriteFile(executable, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.json")

	previousTask, previousStart := runWindowsTaskCommand, startWindowsDetachedDaemon
	t.Cleanup(func() {
		runWindowsTaskCommand = previousTask
		startWindowsDetachedDaemon = previousStart
	})
	var taskCalls [][]string
	runWindowsTaskCommand = func(_ context.Context, arguments ...string) error {
		taskCalls = append(taskCalls, append([]string(nil), arguments...))
		return nil
	}
	var startedExecutable string
	var startedArguments []string
	startWindowsDetachedDaemon = func(path string, arguments []string) error {
		startedExecutable = path
		startedArguments = append([]string(nil), arguments...)
		return nil
	}

	if err := installWindowsCurrentUserService(context.Background(), executable, configPath, "https://api.example.test"); err != nil {
		t.Fatal(err)
	}
	if len(taskCalls) != 1 || len(taskCalls[0]) < 2 || taskCalls[0][0] != "/Create" {
		t.Fatalf("task calls=%q, want one create", taskCalls)
	}
	if startedExecutable != executable {
		t.Fatalf("started executable=%q want=%q", startedExecutable, executable)
	}
	wantArguments := []string{"__local-daemon", "--config", configPath, "--server", "https://api.example.test"}
	if !reflect.DeepEqual(startedArguments, wantArguments) {
		t.Fatalf("started arguments=%q want=%q", startedArguments, wantArguments)
	}
}

func testWindowsDaemonLock(t *testing.T, identity windowsDaemonProcessIdentity) windowsDaemonPIDLock {
	t.Helper()
	executable, digest, err := normalizedWindowsDaemonIdentity(identity.Executable, identity.Arguments)
	if err != nil {
		t.Fatal(err)
	}
	return windowsDaemonPIDLock{Record: windowsDaemonOwnerRecord{Schema: windowsDaemonOwnerSchema, PID: identity.PID, CreationTimeUnixNano: identity.CreationTime.UnixNano(), Executable: executable, ArgumentsSHA256: digest}}
}

func TestStopOwnedWindowsDaemonTerminatesOnlyExactRecordedProcess(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "pb.exe")
	if err := os.WriteFile(executable, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	identity := windowsDaemonProcessIdentity{PID: 4242, OwnerSID: "S-1-5-21-100", Executable: executable, Arguments: []string{executable, "__local-daemon"}, CreationTime: time.Now().UTC()}
	record := testWindowsDaemonLock(t, identity)
	process := &fakeWindowsDaemonProcess{identity: identity}
	previousRead, previousOpen := readWindowsDaemonPIDLock, openWindowsDaemonProcess
	t.Cleanup(func() { readWindowsDaemonPIDLock, openWindowsDaemonProcess = previousRead, previousOpen })
	readWindowsDaemonPIDLock = func(string, string) (windowsDaemonPIDLock, error) { return record, nil }
	openWindowsDaemonProcess = func(pid uint32) (windowsDaemonProcess, error) {
		if pid != identity.PID {
			t.Fatalf("opened PID %d, want %d", pid, identity.PID)
		}
		return process, nil
	}
	if err := stopOwnedWindowsDaemon(context.Background(), filepath.Join(t.TempDir(), "daemon.lock"), identity.OwnerSID, executable); err != nil {
		t.Fatal(err)
	}
	if !process.terminated {
		t.Fatal("validated Paperboat local daemon was not terminated")
	}
	if process.deadline.IsZero() || process.deadline.After(time.Now().Add(10*time.Second)) {
		t.Fatalf("daemon termination deadline = %s", process.deadline)
	}
}

func TestWindowsDaemonOwnerRecordRoundTripsExactIdentity(t *testing.T) {
	ownerSID, err := currentWindowsUserSID()
	if err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(t.TempDir(), "pb.exe")
	if err := os.WriteFile(executable, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	identity := windowsDaemonProcessIdentity{PID: 8181, Executable: executable, Arguments: []string{executable, "__local-daemon", "--server", "https://api.example.test"}, CreationTime: time.Now().UTC()}
	lock := testWindowsDaemonLock(t, identity)
	path := filepath.Join(t.TempDir(), "daemon.lock.owner.json")
	if err := writeWindowsDaemonOwnerRecord(path, ownerSID, lock.Record); err != nil {
		t.Fatal(err)
	}
	loaded, err := readWindowsDaemonOwnerRecord(path, ownerSID)
	if err != nil || !reflect.DeepEqual(loaded, lock.Record) {
		t.Fatalf("owner record=%+v want=%+v error=%v", loaded, lock.Record, err)
	}
}

func TestStopOwnedWindowsDaemonTreatsExactStalePIDAsRemoved(t *testing.T) {
	previousRead, previousOpen := readWindowsDaemonPIDLock, openWindowsDaemonProcess
	t.Cleanup(func() { readWindowsDaemonPIDLock, openWindowsDaemonProcess = previousRead, previousOpen })
	readWindowsDaemonPIDLock = func(string, string) (windowsDaemonPIDLock, error) {
		return windowsDaemonPIDLock{Record: windowsDaemonOwnerRecord{PID: 9999}}, nil
	}
	openWindowsDaemonProcess = func(uint32) (windowsDaemonProcess, error) { return nil, os.ErrNotExist }
	if err := stopOwnedWindowsDaemon(context.Background(), `C:\state\daemon.lock`, "S-1-5-21-100", `C:\Paperboat\pb.exe`); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultReadWindowsDaemonPIDLockRejectsLegacyOrPartialOwnerRecord(t *testing.T) {
	ownerSID, err := currentWindowsUserSID()
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(t.TempDir(), "daemon.lock")
	if err := os.WriteFile(lockPath, []byte("5652\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsLockACL(lockPath, ownerSID); err != nil {
		t.Fatal(err)
	}
	lockFile, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lockFile.Close()
	var region windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(lockFile.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &region); err != nil {
		t.Fatal(err)
	}
	defer windows.UnlockFileEx(windows.Handle(lockFile.Fd()), 0, 1, 0, &region)
	if _, err := defaultReadWindowsDaemonPIDLock(lockPath, ownerSID); !errors.Is(err, errUnsafeWindowsDaemonProcess) {
		t.Fatalf("legacy lock error = %v", err)
	}
	ownerPath := lockPath + ".owner.json"
	if err := os.WriteFile(ownerPath, []byte(`{"schema":"paperboat.windows-local-daemon-owner/v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsLockACL(ownerPath, ownerSID); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultReadWindowsDaemonPIDLock(lockPath, ownerSID); !errors.Is(err, errUnsafeWindowsDaemonProcess) {
		t.Fatalf("partial owner record error = %v", err)
	}
}

func TestValidateOwnedWindowsDaemonRejectsForeignSIDPathCommandAndPIDReuse(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "pb.exe")
	foreign := filepath.Join(t.TempDir(), "foreign.exe")
	for _, path := range []string{executable, foreign} {
		if err := os.WriteFile(path, []byte("fixture"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	valid := windowsDaemonProcessIdentity{PID: 42, OwnerSID: "S-1-5-21-100", Executable: executable, Arguments: []string{executable, "__local-daemon"}, CreationTime: time.Now().UTC()}
	record := testWindowsDaemonLock(t, valid)
	tests := map[string]windowsDaemonProcessIdentity{
		"foreign SID": func() windowsDaemonProcessIdentity { value := valid; value.OwnerSID = "S-1-5-21-200"; return value }(),
		"foreign path": func() windowsDaemonProcessIdentity {
			value := valid
			value.Executable, value.Arguments[0] = foreign, foreign
			return value
		}(),
		"wrong command": func() windowsDaemonProcessIdentity {
			value := valid
			value.Arguments = []string{executable, "serve"}
			return value
		}(),
		"PID reuse": func() windowsDaemonProcessIdentity {
			value := valid
			value.CreationTime = valid.CreationTime.Add(time.Nanosecond)
			return value
		}(),
	}
	for name, identity := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateOwnedWindowsDaemon(identity, record, valid.OwnerSID); !errors.Is(err, errUnsafeWindowsDaemonProcess) {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
}

func TestStopOwnedWindowsDaemonChecksCanceledContextBeforeTermination(t *testing.T) {
	previousRead := readWindowsDaemonPIDLock
	t.Cleanup(func() { readWindowsDaemonPIDLock = previousRead })
	readWindowsDaemonPIDLock = func(string, string) (windowsDaemonPIDLock, error) {
		t.Fatal("read after cancellation")
		return windowsDaemonPIDLock{}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := stopOwnedWindowsDaemon(ctx, `C:\state\daemon.lock`, "S-1-5-21-100", `C:\Paperboat\pb.exe`); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled stop error = %v", err)
	}
}

func TestStopOwnedWindowsDaemonPropagatesBoundedWaitTimeout(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "pb.exe")
	if err := os.WriteFile(executable, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	identity := windowsDaemonProcessIdentity{PID: 77, OwnerSID: "S-1-5-21-100", Executable: executable, Arguments: []string{executable, "__local-daemon"}, CreationTime: time.Now().UTC()}
	process := &fakeWindowsDaemonProcess{identity: identity, terminateErr: context.DeadlineExceeded}
	previousRead, previousOpen := readWindowsDaemonPIDLock, openWindowsDaemonProcess
	t.Cleanup(func() { readWindowsDaemonPIDLock, openWindowsDaemonProcess = previousRead, previousOpen })
	readWindowsDaemonPIDLock = func(string, string) (windowsDaemonPIDLock, error) { return testWindowsDaemonLock(t, identity), nil }
	openWindowsDaemonProcess = func(uint32) (windowsDaemonProcess, error) { return process, nil }
	if err := stopOwnedWindowsDaemon(context.Background(), `C:\state\daemon.lock`, identity.OwnerSID, executable); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v", err)
	}
}

func TestRemoveWindowsCurrentUserServiceIgnoresMissingTaskAndStaleLock(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "pb.exe")
	if err := os.WriteFile(executable, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	previousTask, previousRead := runWindowsTaskCommand, readWindowsDaemonPIDLock
	t.Cleanup(func() { runWindowsTaskCommand, readWindowsDaemonPIDLock = previousTask, previousRead })
	runWindowsTaskCommand = func(context.Context, ...string) error { return errors.New("task does not exist") }
	readWindowsDaemonPIDLock = func(string, string) (windowsDaemonPIDLock, error) { return windowsDaemonPIDLock{}, os.ErrNotExist }
	if err := removeWindowsCurrentUserService(context.Background(), executable); err != nil {
		t.Fatal(err)
	}
}
