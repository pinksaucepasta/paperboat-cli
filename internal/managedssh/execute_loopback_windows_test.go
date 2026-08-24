//go:build windows

package managedssh

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

type nativeOpenSSHEOFStream struct {
	closed    atomic.Bool
	wrote     atomic.Bool
	writeSeen chan struct{}
	closedCh  chan struct{}
	writeOnce sync.Once
	closeOnce sync.Once
}

func (s *nativeOpenSSHEOFStream) Read([]byte) (int, error) {
	select {
	case <-s.writeSeen:
	case <-s.closedCh:
	}
	return 0, io.EOF
}
func (s *nativeOpenSSHEOFStream) Write(value []byte) (int, error) {
	s.wrote.Store(true)
	s.writeOnce.Do(func() { close(s.writeSeen) })
	return len(value), nil
}
func (*nativeOpenSSHEOFStream) CloseWrite() error { return nil }
func (s *nativeOpenSSHEOFStream) Close() error {
	s.closed.Store(true)
	s.closeOnce.Do(func() { close(s.closedCh) })
	return nil
}

func TestLoopbackOpenSSHExecutorVerifiesRealNativeSSHProcess(t *testing.T) {
	stream := &nativeOpenSSHEOFStream{writeSeen: make(chan struct{}), closedCh: make(chan struct{})}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	err := (LoopbackOpenSSHExecutor{}).Execute(ctx, "ssh", func(port uint16) []string {
		return []string{
			"-F", "NUL",
			"-o", "ProxyCommand=none",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=NUL",
			"-o", "GlobalKnownHostsFile=NUL",
			"-o", "LogLevel=QUIET",
			"-p", strconv.Itoa(int(port)),
			"paperboat-test@127.0.0.1",
		}
	}, os.Environ(), stream)
	if err == nil {
		t.Fatal("native OpenSSH unexpectedly completed against the EOF test stream")
	}
	if errors.Is(err, ErrSSHLoopbackOwner) || errors.Is(err, ErrSSHLoopbackAccept) || errors.Is(err, ErrSSHLoopbackShutdown) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("native OpenSSH loopback lifecycle error=%v", err)
	}
	if !stream.wrote.Load() || !stream.closed.Load() {
		t.Fatalf("authenticated test stream wrote=%t closed=%t", stream.wrote.Load(), stream.closed.Load())
	}
}

const (
	loopbackJobTestRole    = "PAPERBOAT_TEST_LOOPBACK_JOB_ROLE"
	loopbackJobTestPIDFile = "PAPERBOAT_TEST_LOOPBACK_JOB_PID_FILE"
	loopbackJobTestGate    = "PAPERBOAT_TEST_LOOPBACK_JOB_GATE"
)

func TestOpenSSHLoopbackJobKillsAndReapsProcessTree(t *testing.T) {
	switch os.Getenv(loopbackJobTestRole) {
	case "child":
		for {
			time.Sleep(time.Hour)
		}
	case "parent":
		gate := os.Getenv(loopbackJobTestGate)
		for {
			if _, err := os.Stat(gate); err == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		child := exec.Command(os.Args[0], "-test.run=^TestOpenSSHLoopbackJobKillsAndReapsProcessTree$")
		child.Env = append(os.Environ(), loopbackJobTestRole+"=child")
		if err := child.Start(); err != nil {
			panic(err)
		}
		if err := os.WriteFile(os.Getenv(loopbackJobTestPIDFile), []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
			panic(err)
		}
		for {
			time.Sleep(time.Hour)
		}
	}

	pidFile := filepath.Join(t.TempDir(), "child.pid")
	gateFile := filepath.Join(t.TempDir(), "assigned.gate")
	command := exec.Command(os.Args[0], "-test.run=^TestOpenSSHLoopbackJobKillsAndReapsProcessTree$")
	command.Env = append(os.Environ(), loopbackJobTestRole+"=parent", loopbackJobTestPIDFile+"="+pidFile, loopbackJobTestGate+"="+gateFile)
	command.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
	processValue, err := startOpenSSHLoopbackProcess(command)
	if err != nil {
		t.Fatal(err)
	}
	process := processValue.(*openSSHLoopbackProcess)
	if err := os.WriteFile(gateFile, []byte("assigned"), 0o600); err != nil {
		_ = process.Kill()
		_ = process.Wait()
		t.Fatal(err)
	}
	var cleanup sync.Once
	stop := func() {
		cleanup.Do(func() {
			_ = process.Kill()
			_ = process.Wait()
		})
	}
	defer stop()
	childPID := waitForLoopbackJobChildPID(t, pidFile)
	childHandle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, childPID)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.Close(childHandle)
	if err := process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err == nil {
		t.Fatal("terminated job parent returned success")
	}
	cleanup.Do(func() {})
	status, err := windows.WaitForSingleObject(childHandle, 2_000)
	if err != nil || status != windows.WAIT_OBJECT_0 {
		t.Fatalf("job child was not terminated: status=%d error=%v", status, err)
	}
}

func waitForLoopbackJobChildPID(t *testing.T, path string) uint32 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		body, err := os.ReadFile(path)
		if err == nil {
			pid, parseErr := strconv.ParseUint(strings.TrimSpace(string(body)), 10, 32)
			if parseErr != nil || pid == 0 {
				t.Fatalf("invalid child PID %q: %v", body, parseErr)
			}
			return uint32(pid)
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("job child PID was not published")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
