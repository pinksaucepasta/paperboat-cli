//go:build !windows

package service

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type outputCommandRunner struct {
	calls   [][]string
	outputs []string
	errors  []error
}

func (r *outputCommandRunner) Run(ctx context.Context, name string, args ...string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.calls = append(r.calls, append([]string{name}, args...))
	return r.nextError()
}

func (r *outputCommandRunner) Output(ctx context.Context, name string, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	r.calls = append(r.calls, append([]string{name}, args...))
	index := len(r.calls) - 1
	var output string
	if index < len(r.outputs) {
		output = r.outputs[index]
	}
	return output, r.nextErrorAt(index)
}

func (r *outputCommandRunner) nextError() error {
	return r.nextErrorAt(len(r.calls) - 1)
}

func (r *outputCommandRunner) nextErrorAt(index int) error {
	if index >= 0 && index < len(r.errors) {
		return r.errors[index]
	}
	return nil
}

func TestSystemdNativeLifecycleStateAndCommands(t *testing.T) {
	runner := &outputCommandRunner{outputs: []string{
		"LoadState=loaded\nUnitFileState=disabled\nActiveState=inactive\nSubState=dead\n",
	}}
	controller := SystemdController{Runner: runner, Unit: "paperboat-hostd.service"}
	status, err := controller.Inspect(context.Background(), "/etc/systemd/system/paperboat-hostd.service")
	if err != nil {
		t.Fatal(err)
	}
	if !status.Registered || status.Enabled || status.Running || status.Ready {
		t.Fatalf("disabled status=%+v", status)
	}
	runner.outputs = []string{
		"LoadState=loaded\nUnitFileState=disabled\nActiveState=inactive\nSubState=dead\n",
		"LoadState=loaded\nUnitFileState=enabled\nActiveState=active\nSubState=running\n",
	}
	status, err = controller.Inspect(context.Background(), "")
	if err != nil || !status.Registered || !status.Enabled || !status.Running || !status.Ready {
		t.Fatalf("running status=%+v err=%v", status, err)
	}
	if err := controller.Enable(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := controller.Stop(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := controller.Disable(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"systemctl show paperboat-hostd.service --property=LoadState --property=UnitFileState --property=ActiveState --property=SubState",
		"systemctl show paperboat-hostd.service --property=LoadState --property=UnitFileState --property=ActiveState --property=SubState",
		"systemctl daemon-reload",
		"systemctl enable paperboat-hostd.service",
		"systemctl start paperboat-hostd.service",
		"systemctl is-active --quiet paperboat-hostd.service",
		"systemctl stop paperboat-hostd.service",
		"systemctl disable paperboat-hostd.service",
	}
	if len(runner.calls) != len(want) {
		t.Fatalf("calls=%v", runner.calls)
	}
	for index, call := range runner.calls {
		if got := strings.Join(call, " "); got != want[index] {
			t.Fatalf("call %d=%q want %q", index, got, want[index])
		}
	}
}

func TestSystemdNativeLifecycleAbsentAndCancellation(t *testing.T) {
	absent := &CommandError{Tool: "systemctl", Output: "Unit paperboat-hostd.service not loaded.", Cause: errors.New("exit status 1")}
	runner := &outputCommandRunner{errors: []error{absent}}
	controller := SystemdController{Runner: runner}
	status, err := controller.Inspect(context.Background(), "")
	if err != nil || status != (NativeControllerStatus{}) {
		t.Fatalf("absent status=%+v err=%v", status, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := controller.Stop(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled stop=%v", err)
	}
}

func TestLaunchdNativeLifecycleStopBootsOutAndStartReRegistersDeclaration(t *testing.T) {
	absent := errors.New("launchctl: service not found")
	runner := &outputCommandRunner{outputs: []string{"state = running\n"}, errors: []error{nil, nil, nil, absent}}
	controller := LaunchdController{Runner: runner, UID: 501, Label: "com.pinksaucepasta.paperboat.hostd"}
	status, err := controller.Inspect(context.Background(), "/Library/LaunchDaemons/com.pinksaucepasta.paperboat.hostd.plist")
	if err != nil || !status.Registered || !status.Enabled || !status.Running || !status.Ready {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	if err := controller.Stop(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := controller.Disable(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(context.Background(), "/Library/LaunchDaemons/com.pinksaucepasta.paperboat.hostd.plist"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"launchctl print system/com.pinksaucepasta.paperboat.hostd",
		"launchctl bootout system/com.pinksaucepasta.paperboat.hostd",
		"launchctl bootout system/com.pinksaucepasta.paperboat.hostd",
		"launchctl kickstart -k system/com.pinksaucepasta.paperboat.hostd",
		"launchctl bootstrap system /Library/LaunchDaemons/com.pinksaucepasta.paperboat.hostd.plist",
		"launchctl kickstart -k system/com.pinksaucepasta.paperboat.hostd",
		"launchctl print system/com.pinksaucepasta.paperboat.hostd",
	}
	if len(runner.calls) != len(want) {
		t.Fatalf("calls=%v", runner.calls)
	}
	for index, call := range runner.calls {
		if got := strings.Join(call, " "); got != want[index] {
			t.Fatalf("call %d=%q want %q", index, got, want[index])
		}
	}
}

func TestLaunchdInspectRecognizesKeepAliveProcessProjection(t *testing.T) {
	output := `system/com.pinksaucepasta.paperboat.updated = {
	active count = 1
	state = waiting
	pid = 81626
}`
	runner := &outputCommandRunner{outputs: []string{output}}
	status, err := (LaunchdController{Runner: runner, UID: 501, Label: UpdaterLabel}).Inspect(context.Background(), "")
	if err != nil || !status.Registered || !status.Enabled || !status.Running || !status.Ready {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestLaunchdInspectRequiresTopLevelHealthyProjection(t *testing.T) {
	tests := []struct {
		name   string
		output string
		ready  bool
	}{
		{
			name: "running state",
			output: `system/com.pinksaucepasta.paperboat.hostd = {
	state = running
}`,
			ready: true,
		},
		{
			name: "spawn scheduled",
			output: `system/com.pinksaucepasta.paperboat.hostd = {
	active count = 0
	state = spawn scheduled
last exit code = 1
}`,
		},
		{
			name: "nested running state",
			output: `system/com.pinksaucepasta.paperboat.hostd = {
	state = waiting
	properties = {
	state = running
	active count = 1
	pid = 81626
	}
}`,
		},
		{
			name: "nested process projection",
			output: `system/com.pinksaucepasta.paperboat.hostd = {
	state = waiting
	properties = {
	active count = 1
	pid = 81626
	}
}`,
		},
		{
			name: "top-level process projection",
			output: `system/com.pinksaucepasta.paperboat.hostd = {
	active count = 1
	state = waiting
	pid = 81626
}`,
			ready: true,
		},
		{
			name: "zero pid",
			output: `system/com.pinksaucepasta.paperboat.hostd = {
	active count = 1
	state = waiting
	pid = 0
}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &outputCommandRunner{outputs: []string{test.output}}
			status, err := (LaunchdController{Runner: runner, UID: 501, Label: HostdLabel}).Inspect(context.Background(), "")
			if err != nil || status.Ready != test.ready || status.Running != test.ready {
				t.Fatalf("status=%+v err=%v", status, err)
			}
		})
	}
}

func TestLaunchdNativeLifecycleAbsentIsIdempotent(t *testing.T) {
	absent := errors.New("launchctl: service not found")
	runner := &outputCommandRunner{errors: []error{absent}}
	controller := LaunchdController{Runner: runner, UID: 501}
	status, err := controller.Inspect(context.Background(), "")
	if err != nil || status != (NativeControllerStatus{}) {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	if err := controller.Stop(context.Background(), ""); err != nil {
		t.Fatalf("stop absent=%v", err)
	}
	if err := controller.Disable(context.Background(), ""); err != nil {
		t.Fatalf("disable absent=%v", err)
	}
}
