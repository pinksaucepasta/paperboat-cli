//go:build windows

package localdaemon

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

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
