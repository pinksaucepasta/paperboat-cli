//go:build darwin || linux

package hostruntimecmd

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releaseeligibility"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/updated"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
)

func runUpdated(ctx context.Context, args []string, _ io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("updated", flag.ContinueOnError)
	flags.SetOutput(stderr)
	now := flags.Bool("now", false, "perform one manual update")
	if flags.Parse(args) != nil || flags.NArg() != 0 || os.Geteuid() != 0 {
		return errors.New("invalid paperboat-updated invocation")
	}
	notifier, err := service.NewProcessNotifier()
	if err != nil {
		return err
	}
	if err := notifier.Starting(); err != nil {
		return err
	}
	failInitialization := func(err error) error {
		if err == nil {
			return nil
		}
		return errors.Join(err, notifier.Degraded("updater initialization failed"))
	}
	stateRoot := os.Getenv("PAPERBOAT_UPDATE_STATE_ROOT")
	binary, binaryRollback, binaryStaged := os.Getenv("PAPERBOAT_BINARY"), os.Getenv("PAPERBOAT_BINARY_ROLLBACK"), os.Getenv("PAPERBOAT_BINARY_STAGED")
	socket, tokenPath, repository, machineID := os.Getenv("PAPERBOAT_HOSTD_SOCKET"), os.Getenv("PAPERBOAT_HOSTD_TOKEN_FILE"), os.Getenv("PAPERBOAT_RELEASE_REPOSITORY"), os.Getenv("PAPERBOAT_MACHINE_ID")
	controlSocket := os.Getenv("PAPERBOAT_UPDATED_SOCKET")
	healthURL := os.Getenv("PAPERBOAT_UPDATE_HEALTH_URL")
	uid, uidErr := strconv.Atoi(os.Getenv("PAPERBOAT_ENROLLED_UID"))
	gid, gidErr := strconv.Atoi(os.Getenv("PAPERBOAT_ENROLLED_GID"))
	paths := []string{stateRoot, binary, binaryRollback, binaryStaged, socket, tokenPath, controlSocket}
	for _, path := range paths {
		if !filepath.IsAbs(path) {
			return failInitialization(errors.New("invalid paperboat-updated environment"))
		}
	}
	if repository == "" || machineID == "" || healthURL == "" || uidErr != nil || gidErr != nil || !validRuntimeIdentity(uid, gid) {
		return failInitialization(errors.New("invalid paperboat-updated environment"))
	}
	token, err := readWorkerToken(tokenPath)
	if err != nil {
		return failInitialization(err)
	}
	restarter, err := updated.NewFixedUpdaterReexec(binary)
	if err != nil {
		return failInitialization(err)
	}
	hostdClient, err := hostdproto.NewClient(socket, token, 31*time.Minute)
	if err != nil {
		return failInitialization(err)
	}
	deferral, err := releaseeligibility.NewFileStore(filepath.Join(stateRoot, "deferral.json"))
	if err != nil {
		return failInitialization(err)
	}
	source := workerupdate.TUFSource{RepositoryURL: repository, StateRoot: filepath.Join(stateRoot, "tuf"), MachineID: machineID, FailureDomain: workerupdate.HostdFailureDomainSource{Client: hostdClient, MachineID: machineID}, Deferral: deferral}
	active, err := resolveUpdatedActive(ctx, filepath.Join(stateRoot, "transaction.json"), buildinfo.Version, source.Active)
	if err != nil {
		return failInitialization(err)
	}
	gate, err := workerupdate.NewDeploymentActivationGate(workerupdate.DeploymentActivationGateConfig{Provider: workerupdate.HostdDeploymentProvider{Client: hostdClient}})
	if err != nil {
		return failInitialization(err)
	}
	updaterService, err := updated.New(updated.Config{StateRoot: stateRoot, Binary: binary, BinaryRollback: binaryRollback, BinaryStaged: binaryStaged, Active: active, WorkerUID: uid, WorkerGID: gid, SocketPath: socket, Token: token, RepositoryURL: repository, MachineID: machineID, Health: updated.HTTPHealth{Endpoint: healthURL}, ActivationGate: gate, ControlSocket: controlSocket, Restarter: restarter})
	if err != nil {
		return failInitialization(err)
	}
	if *now {
		if err := notifier.Ready(); err != nil {
			return errors.Join(err, notifier.Degraded("updater readiness notification failed"))
		}
		_, updateErr := updaterService.UpdateNow(ctx)
		return errors.Join(updateErr, notifier.Stopping())
	}
	return runNotifiedUpdater(ctx, updaterRunnerFunc(func(ctx context.Context, ready func() error) error {
		return updaterService.RunWithReady(ctx, ready)
	}), notifier)
}

type updaterRunner interface {
	Run(context.Context, func() error) error
}

type updaterRunnerFunc func(context.Context, func() error) error

func (f updaterRunnerFunc) Run(ctx context.Context, ready func() error) error {
	return f(ctx, ready)
}

type processNotifier interface {
	Ready() error
	Degraded(string) error
	Stopping() error
	WatchdogInterval() time.Duration
	Watchdog() error
}

// runNotifiedUpdater keeps the systemd notify contract aligned with the
// updater service declaration. The scheduler is run in a child context so a
// failed watchdog notification can stop it before returning the failure. The
// runner invokes ready after its authenticated listener is accepting work.
func runNotifiedUpdater(ctx context.Context, runner updaterRunner, notifier processNotifier) error {
	if ctx == nil || runner == nil || notifier == nil {
		return errors.New("invalid updater lifecycle")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	readyDone := make(chan error, 1)
	go func() {
		done <- runner.Run(runCtx, func() error {
			err := notifier.Ready()
			readyDone <- err
			return err
		})
	}()
	for {
		select {
		case readyErr := <-readyDone:
			if readyErr != nil {
				cancel()
				runErr := <-done
				return errors.Join(readyErr, notifier.Degraded("updater readiness notification failed"), runErr, notifier.Stopping())
			}
			goto running
		case runErr := <-done:
			// A runner that returns after invoking a successful ready callback
			// may win this select before the callback signal is consumed.
			select {
			case readyErr := <-readyDone:
				if readyErr == nil {
					return errors.Join(runErr, notifier.Stopping())
				}
				return errors.Join(runErr, readyErr, notifier.Degraded("updater readiness notification failed"), notifier.Stopping())
			default:
				return errors.Join(runErr, notifier.Degraded("updater exited before readiness"), notifier.Stopping())
			}
		case <-ctx.Done():
			cancel()
			runErr := <-done
			return errors.Join(ctx.Err(), runErr, notifier.Stopping())
		}
	}

running:

	interval := notifier.WatchdogInterval()
	var watchdog <-chan time.Time
	var ticker *time.Ticker
	if interval > 0 {
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
		watchdog = ticker.C
	}
	for {
		select {
		case err := <-done:
			return errors.Join(err, notifier.Stopping())
		case <-ctx.Done():
			cancel()
			runErr := <-done
			return errors.Join(runErr, notifier.Stopping())
		case <-watchdog:
			if err := notifier.Watchdog(); err != nil {
				cancel()
				runErr := <-done
				return errors.Join(err, notifier.Degraded("updater watchdog notification failed"), runErr, notifier.Stopping())
			}
		}
	}
}

func resolveUpdatedActive(ctx context.Context, journalPath, version string, resolve func(context.Context, string) (workerupdate.Release, error)) (workerupdate.Release, error) {
	active, err := resolve(ctx, version)
	if err == nil || !errors.Is(err, workerupdate.ErrInvalidRelease) {
		return active, err
	}
	recovered, journalErr := workerupdate.RecoveryReleaseFromJournal(journalPath, version)
	if journalErr != nil {
		return workerupdate.Release{}, err
	}
	if recovered.Version != version {
		_, policyErr := resolve(ctx, recovered.Version)
		if policyErr == nil {
			return recovered, nil
		}
		if !errors.Is(policyErr, workerupdate.ErrInvalidRelease) {
			return workerupdate.Release{}, policyErr
		}
	}
	return recovered, nil
}

func validRuntimeIdentity(uid, gid int) bool {
	return uid > 0 && gid > 0 || uid == 0 && gid == 0
}
