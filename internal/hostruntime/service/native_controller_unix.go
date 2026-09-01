//go:build !windows

package service

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const nativeServiceOperationTimeout = 30 * time.Second

func nativeServiceContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, ErrLifecycleInvalid
	}
	operationCtx, cancel := context.WithTimeout(ctx, nativeServiceOperationTimeout)
	return operationCtx, cancel, nil
}

func (c SystemdController) Inspect(ctx context.Context, _ string) (NativeControllerStatus, error) {
	runner, ok := c.Runner.(OutputRunner)
	if !ok {
		return NativeControllerStatus{}, ErrLifecycleInvalid
	}
	operationCtx, cancel, err := nativeServiceContext(ctx)
	if err != nil {
		return NativeControllerStatus{}, err
	}
	defer cancel()
	arguments := []string{"show", c.unit(), "--property=LoadState", "--property=UnitFileState", "--property=ActiveState", "--property=SubState"}
	if c.User {
		arguments = append([]string{"--user"}, arguments...)
	}
	output, err := runner.Output(operationCtx, "systemctl", arguments...)
	if err != nil {
		if systemdUnitAbsent(err) {
			return NativeControllerStatus{}, nil
		}
		return NativeControllerStatus{}, err
	}
	properties := parseNativeProperties(output)
	if properties["LoadState"] == "not-found" {
		return NativeControllerStatus{}, nil
	}
	registered := properties["LoadState"] == "loaded"
	enabled := properties["UnitFileState"] == "enabled"
	running := properties["ActiveState"] == "active"
	ready := running && (properties["SubState"] == "running" || properties["SubState"] == "exited")
	return NativeControllerStatus{Registered: registered, Enabled: enabled, Running: running, Ready: ready}, nil
}

func (c SystemdController) Enable(ctx context.Context, _ string) error {
	if c.Runner == nil {
		return ErrLifecycleInvalid
	}
	operationCtx, cancel, err := nativeServiceContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	arguments := func(values ...string) []string {
		if c.User {
			return append([]string{"--user"}, values...)
		}
		return values
	}
	if err := c.Runner.Run(operationCtx, "systemctl", arguments("daemon-reload")...); err != nil {
		return err
	}
	return c.Runner.Run(operationCtx, "systemctl", arguments("enable", c.unit())...)
}

func (c SystemdController) Disable(ctx context.Context, _ string) error {
	if c.Runner == nil {
		return ErrLifecycleInvalid
	}
	operationCtx, cancel, err := nativeServiceContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	arguments := []string{"disable", c.unit()}
	if c.User {
		arguments = append([]string{"--user"}, arguments...)
	}
	err = c.Runner.Run(operationCtx, "systemctl", arguments...)
	if systemdUnitAbsent(err) {
		return nil
	}
	return err
}

func (c SystemdController) Start(ctx context.Context, _ string) error {
	if c.Runner == nil {
		return ErrLifecycleInvalid
	}
	operationCtx, cancel, err := nativeServiceContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	arguments := func(values ...string) []string {
		if c.User {
			return append([]string{"--user"}, values...)
		}
		return values
	}
	if err := c.Runner.Run(operationCtx, "systemctl", arguments("start", c.unit())...); err != nil {
		return err
	}
	return c.Runner.Run(operationCtx, "systemctl", arguments("is-active", "--quiet", c.unit())...)
}

func (c SystemdController) Stop(ctx context.Context, _ string) error {
	if c.Runner == nil {
		return ErrLifecycleInvalid
	}
	operationCtx, cancel, err := nativeServiceContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	arguments := []string{"stop", c.unit()}
	if c.User {
		arguments = append([]string{"--user"}, arguments...)
	}
	err = c.Runner.Run(operationCtx, "systemctl", arguments...)
	if systemdUnitAbsent(err) {
		return nil
	}
	return err
}

func (c LaunchdController) Inspect(ctx context.Context, _ string) (NativeControllerStatus, error) {
	runner, ok := c.Runner.(OutputRunner)
	if !ok || c.UID < 0 {
		return NativeControllerStatus{}, ErrLifecycleInvalid
	}
	operationCtx, cancel, err := nativeServiceContext(ctx)
	if err != nil {
		return NativeControllerStatus{}, err
	}
	defer cancel()
	output, err := runner.Output(operationCtx, "launchctl", "print", c.service())
	if err != nil {
		if launchdServiceAbsent(err) {
			return NativeControllerStatus{}, nil
		}
		return NativeControllerStatus{}, err
	}
	running := strings.Contains(output, "state = running")
	return NativeControllerStatus{Registered: true, Enabled: true, Running: running, Ready: running}, nil
}

func (c LaunchdController) Enable(ctx context.Context, path string) error {
	if c.Runner == nil || c.UID < 0 {
		return ErrLifecycleInvalid
	}
	operationCtx, cancel, err := nativeServiceContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	err = c.Runner.Run(operationCtx, "launchctl", "bootstrap", c.domain(), path)
	if err == nil {
		return nil
	}
	if probeErr := c.Runner.Run(operationCtx, "launchctl", "print", c.service()); probeErr == nil {
		return nil
	}
	return err
}

func (c LaunchdController) Disable(ctx context.Context, _ string) error {
	if c.Runner == nil || c.UID < 0 {
		return ErrLifecycleInvalid
	}
	operationCtx, cancel, err := nativeServiceContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	err = c.Runner.Run(operationCtx, "launchctl", "bootout", c.service())
	if launchdServiceAbsent(err) {
		return nil
	}
	return err
}

func (c LaunchdController) Start(ctx context.Context, path string) error {
	if c.Runner == nil || c.UID < 0 {
		return ErrLifecycleInvalid
	}
	operationCtx, cancel, err := nativeServiceContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if err := c.Runner.Run(operationCtx, "launchctl", "kickstart", "-k", c.service()); err != nil {
		// Stop deliberately bootstraps the service out of launchd so KeepAlive
		// cannot restart it behind the transaction's back. Re-register the same
		// declaration before retrying the kickstart on the next Start/Repair.
		if path == "" {
			return err
		}
		if bootstrapErr := c.Runner.Run(operationCtx, "launchctl", "bootstrap", c.domain(), path); bootstrapErr != nil {
			return fmt.Errorf("kickstart %s: %w (bootstrap: %v)", c.service(), err, bootstrapErr)
		}
		if err := c.Runner.Run(operationCtx, "launchctl", "kickstart", "-k", c.service()); err != nil {
			return err
		}
	}
	return c.Runner.Run(operationCtx, "launchctl", "print", c.service())
}

func (c LaunchdController) Stop(ctx context.Context, _ string) error {
	if c.Runner == nil || c.UID < 0 {
		return ErrLifecycleInvalid
	}
	operationCtx, cancel, err := nativeServiceContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	// launchd KeepAlive/RunAtLoad would restart a merely killed service. Boot
	// the job out to make Stop durable, while leaving the declaration plist in
	// place so Start/Repair can bootstrap the exact same bytes again.
	err = c.Runner.Run(operationCtx, "launchctl", "bootout", c.service())
	if launchdServiceAbsent(err) {
		return nil
	}
	return err
}

func (c LaunchdController) domain() string {
	if c.UserDomain {
		return fmt.Sprintf("gui/%d", c.UID)
	}
	return "system"
}

func (c LaunchdController) service() string { return c.domain() + "/" + c.label() }

func parseNativeProperties(output string) map[string]string {
	properties := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			properties[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return properties
}

var (
	_ NativeLifecycleController = SystemdController{}
	_ NativeLifecycleController = LaunchdController{}
)
