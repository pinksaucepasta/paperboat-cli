//go:build darwin || linux

package updated

import (
	"context"
	"errors"
	"runtime"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
)

// FixedSupervisorActivator is the only service-manager operation the updater
// can perform. It has no caller-supplied executable, arguments, unit, or
// launchd label. The journal remains durable before these calls because the
// updater itself may be restarted by the second operation.
type FixedSupervisorActivator struct {
	Platform string
	Runner   service.Runner
}

// FixedUpdaterRestarter reloads only the updater after a committed worker
// update. The target is fixed by platform so an enrolled user cannot select a
// service, executable, or argument through the control socket.
type FixedUpdaterRestarter struct {
	Platform string
	Runner   service.Runner
}

func (r FixedUpdaterRestarter) Restart(ctx context.Context) error {
	if r.Runner == nil || r.Platform != runtime.GOOS {
		return errors.New("invalid fixed updater restarter")
	}
	switch r.Platform {
	case "linux":
		return r.Runner.Run(ctx, "systemctl", "--no-block", "restart", "paperboat-updated.service")
	case "darwin":
		return r.Runner.Run(ctx, "launchctl", "kickstart", "-k", "system/com.pinksaucepasta.paperboat.updated")
	default:
		return errors.New("unsupported updater platform")
	}
}

func (a FixedSupervisorActivator) Activate(ctx context.Context) error {
	return a.restart(ctx)
}

func (a FixedSupervisorActivator) Rollback(ctx context.Context) error {
	return a.restart(ctx)
}

func (a FixedSupervisorActivator) restart(ctx context.Context) error {
	if a.Runner == nil || a.Platform != runtime.GOOS {
		return errors.New("invalid fixed supervisor activator")
	}
	switch a.Platform {
	case "linux":
		if err := a.Runner.Run(ctx, "systemctl", "restart", "paperboat-hostd.service"); err != nil {
			return err
		}
		return a.Runner.Run(ctx, "systemctl", "restart", "paperboat-updated.service")
	case "darwin":
		if err := a.Runner.Run(ctx, "launchctl", "kickstart", "-k", "system/com.pinksaucepasta.paperboat.hostd"); err != nil {
			return err
		}
		return a.Runner.Run(ctx, "launchctl", "kickstart", "-k", "system/com.pinksaucepasta.paperboat.updated")
	default:
		return errors.New("unsupported supervisor platform")
	}
}
