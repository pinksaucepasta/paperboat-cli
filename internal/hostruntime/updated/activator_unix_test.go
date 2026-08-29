//go:build darwin || linux

package updated

import (
	"context"
	"reflect"
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

func TestFixedSupervisorActivatorReloadsHostdBeforeUpdater(t *testing.T) {
	runner := &recordingRunner{}
	if err := (FixedSupervisorActivator{Platform: runtime.GOOS, Runner: runner}).Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"launchctl kickstart -k system/com.pinksaucepasta.paperboat.hostd",
		"launchctl kickstart -k system/com.pinksaucepasta.paperboat.updated",
	}
	if runtime.GOOS == "linux" {
		want = []string{
			"systemctl restart paperboat-hostd.service",
			"systemctl restart paperboat-updated.service",
		}
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("restart calls = %q, want %q", runner.calls, want)
	}
}
