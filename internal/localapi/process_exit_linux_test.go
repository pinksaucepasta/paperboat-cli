//go:build linux

package localapi

import (
	"os/exec"
	"testing"
	"time"
)

func TestProcessExitWatcherTracksExactLinuxProcessLifetime(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "sleep 30")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done, closeWatcher := watchProcessExit(command.Process.Pid)
	defer closeWatcher()
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pidfd did not report exact process exit")
	}
}

func TestClosingProcessExitWatcherDoesNotReportLiveProcessExit(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "sleep 30")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	done, closeWatcher := watchProcessExit(command.Process.Pid)
	closeWatcher()
	select {
	case <-done:
		t.Fatal("closing pidfd reported a live process as exited")
	case <-time.After(20 * time.Millisecond):
	}
}
