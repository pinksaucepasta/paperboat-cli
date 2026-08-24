//go:build darwin || linux

package hostruntimecmd

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/supervisorupdate"
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
	stateRoot, current, rollback, staged := os.Getenv("PAPERBOAT_UPDATE_STATE_ROOT"), os.Getenv("PAPERBOAT_RUNTIME_CURRENT"), os.Getenv("PAPERBOAT_RUNTIME_ROLLBACK"), os.Getenv("PAPERBOAT_RUNTIME_STAGED")
	cliCurrent, cliRollback := os.Getenv("PAPERBOAT_CLI_CURRENT"), os.Getenv("PAPERBOAT_CLI_ROLLBACK")
	socket, tokenPath, repository, machineID := os.Getenv("PAPERBOAT_HOSTD_SOCKET"), os.Getenv("PAPERBOAT_HOSTD_TOKEN_FILE"), os.Getenv("PAPERBOAT_RELEASE_REPOSITORY"), os.Getenv("PAPERBOAT_MACHINE_ID")
	releaseRoot, hostdBinary, updaterBinary, launcherBinary := os.Getenv("PAPERBOAT_RELEASE_ROOT"), os.Getenv("PAPERBOAT_HOSTD_BINARY"), os.Getenv("PAPERBOAT_UPDATER_BINARY"), os.Getenv("PAPERBOAT_LAUNCHER_BINARY")
	controlSocket := os.Getenv("PAPERBOAT_UPDATED_SOCKET")
	healthURL := os.Getenv("PAPERBOAT_UPDATE_HEALTH_URL")
	uid, uidErr := strconv.Atoi(os.Getenv("PAPERBOAT_ENROLLED_UID"))
	gid, gidErr := strconv.Atoi(os.Getenv("PAPERBOAT_ENROLLED_GID"))
	for _, path := range []string{stateRoot, releaseRoot, current, rollback, staged, cliCurrent, cliRollback, socket, tokenPath, controlSocket, hostdBinary, updaterBinary, launcherBinary} {
		if !filepath.IsAbs(path) {
			return errors.New("invalid paperboat-updated environment")
		}
	}
	if repository == "" || machineID == "" || healthURL == "" || uidErr != nil || gidErr != nil || !validRuntimeIdentity(uid, gid) {
		return errors.New("invalid paperboat-updated environment")
	}
	token, err := readWorkerToken(tokenPath)
	if err != nil {
		return err
	}
	source := workerupdate.TUFSource{RepositoryURL: repository, StateRoot: filepath.Join(stateRoot, "tuf"), MachineID: machineID}
	active, err := source.Active(ctx, buildinfo.Version)
	if err != nil {
		return err
	}
	rollbackRoot := filepath.Join(releaseRoot, "supervisor-rollback")
	stagedRoot := filepath.Join(releaseRoot, "supervisor-staged")
	for _, directory := range []string{rollbackRoot, stagedRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return err
		}
	}
	supervisorPaths := supervisorupdate.Paths{
		StatePath:    filepath.Join(stateRoot, "supervisor-transaction.json"),
		HostdCurrent: hostdBinary, HostdRollback: filepath.Join(rollbackRoot, "paperboat-hostd"), HostdStaged: filepath.Join(stagedRoot, "paperboat-hostd"),
		UpdaterCurrent: updaterBinary, UpdaterRollback: filepath.Join(rollbackRoot, "paperboat-updated"), UpdaterStaged: filepath.Join(stagedRoot, "paperboat-updated"),
		LauncherCurrent: launcherBinary, LauncherRollback: filepath.Join(rollbackRoot, "pb"), LauncherStaged: filepath.Join(stagedRoot, "pb"),
	}
	updaterService, err := updated.New(updated.Config{StateRoot: stateRoot, RuntimeCurrent: current, RuntimeRollback: rollback, RuntimeStaged: staged, CLICurrent: cliCurrent, CLIRollback: cliRollback, Active: active, WorkerUID: uid, WorkerGID: gid, SocketPath: socket, Token: token, RepositoryURL: repository, MachineID: machineID, Health: updated.HTTPHealth{Endpoint: healthURL}, ControlSocket: controlSocket, SupervisorPaths: supervisorPaths, SupervisorActivator: updated.FixedSupervisorActivator{Platform: runtime.GOOS, Runner: service.ExecRunner{}}})
	if err != nil {
		return err
	}
	if *now {
		_, err := updaterService.UpdateNow(ctx)
		return err
	}
	return updaterService.Run(ctx)
}

func validRuntimeIdentity(uid, gid int) bool {
	return uid > 0 && gid > 0 || uid == 0 && gid == 0
}
