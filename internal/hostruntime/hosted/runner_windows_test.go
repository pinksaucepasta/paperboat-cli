//go:build windows

package hosted

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestLimitedBufferClosesScopedJobOnceOnOutputLimit(t *testing.T) {
	var calls atomic.Int32
	buffer := limitedBuffer{limit: 2, abort: func() error {
		calls.Add(1)
		return nil
	}}
	if _, err := buffer.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := buffer.Write([]byte("d")); err != nil {
		t.Fatal(err)
	}
	if !buffer.Exceeded() || string(buffer.Bytes()) != "ab" || calls.Load() != 1 {
		t.Fatalf("limited buffer = exceeded:%v bytes:%q aborts:%d", buffer.Exceeded(), buffer.Bytes(), calls.Load())
	}
}

func TestCommandEnvironmentUsesDoubleNULTerminator(t *testing.T) {
	empty, err := commandEnvironment([]string{})
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 2 || empty[0] != 0 || empty[1] != 0 {
		t.Fatalf("empty environment = %#v, want two NULs", empty)
	}
	populated, err := commandEnvironment([]string{"B=2", "A=1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(populated) < 2 || populated[len(populated)-1] != 0 || populated[len(populated)-2] != 0 {
		t.Fatalf("environment is not double-NUL terminated: %#v", populated)
	}
}

func TestExecRunnerUsesScopedJobOnWindows(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatal(err)
	}
	t.Setenv("PAPERBOAT_WINDOWS_OWNER_WORKLOAD", "1")
	runner := ExecRunner{OwnerSID: user.User.Sid.String()}
	command := `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	output, err := runner.Run(context.Background(), Command{Path: command, Args: []string{"-NoProfile", "-NonInteractive", "-Command", "[Console]::Out.Write('123456789')"}, Dir: t.TempDir(), Env: os.Environ(), OutputLimit: 4})
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("output limit error = %v, output = %q", err, output)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = runner.Run(ctx, Command{Path: command, Args: []string{"-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 10"}, Dir: t.TempDir(), Env: os.Environ(), OutputLimit: 1024})
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("context error = %v, process error = %v", ctx.Err(), err)
	}
}
