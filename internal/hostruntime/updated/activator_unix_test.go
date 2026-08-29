//go:build darwin || linux

package updated

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

type recordingRunner struct{ calls []string }

func (r *recordingRunner) Run(_ context.Context, name string, arguments ...string) error {
	r.calls = append(r.calls, strings.Join(append([]string{name}, arguments...), " "))
	return nil
}

func (r *recordingRunner) Output(context.Context, string, ...string) (string, error) {
	return "", nil
}

func TestFixedUpdaterRestarterUsesOnlyPlatformService(t *testing.T) {
	runner := &recordingRunner{}
	if err := (FixedUpdaterRestarter{Platform: runtime.GOOS, Runner: runner}).Restart(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := "launchctl kickstart -k system/com.pinksaucepasta.paperboat.updated"
	if runtime.GOOS == "linux" {
		want = "systemctl --no-block restart paperboat-updated.service"
	}
	if len(runner.calls) != 1 || runner.calls[0] != want {
		t.Fatalf("restart calls = %q, want %q", runner.calls, want)
	}
}
