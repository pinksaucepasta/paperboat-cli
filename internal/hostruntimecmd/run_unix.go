//go:build darwin || linux

package hostruntimecmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/runtime"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
)

func runProduction(ctx context.Context, output io.Writer) error {
	notifier, err := service.NewProcessNotifier()
	if err != nil {
		return err
	}
	if err := notifier.Starting(); err != nil {
		return err
	}
	host, err := runtime.NewProductionHost(ctx, buildinfo.Version, os.Getenv)
	if err != nil {
		_ = notifier.Degraded("runtime initialization failed")
		return err
	}
	if err := host.Start(ctx); err != nil {
		_ = notifier.Degraded("runtime startup failed")
		return err
	}
	if err := notifier.Ready(); err != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		return errors.Join(err, host.Shutdown(shutdownCtx))
	}
	fmt.Fprintln(output, "pb host runtime ready")
	watchdogInterval := notifier.WatchdogInterval()
	var watchdog <-chan time.Time
	var ticker *time.Ticker
	if watchdogInterval > 0 {
		ticker = time.NewTicker(watchdogInterval)
		defer ticker.Stop()
		watchdog = ticker.C
	}
	var runErr error
run:
	for {
		select {
		case <-ctx.Done():
			runErr = notifier.Draining()
			break run
		case <-watchdog:
			if err := notifier.Watchdog(); err != nil {
				runErr = errors.Join(err, notifier.Degraded("watchdog notification failed"))
				break run
			}
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return errors.Join(runErr, notifier.Stopping(), host.Shutdown(shutdownCtx))
}
