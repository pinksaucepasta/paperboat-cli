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

	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
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
	controlSocket := os.Getenv("PAPERBOAT_UPDATED_SOCKET")
	healthURL := os.Getenv("PAPERBOAT_UPDATE_HEALTH_URL")
	uid, uidErr := strconv.Atoi(os.Getenv("PAPERBOAT_ENROLLED_UID"))
	gid, gidErr := strconv.Atoi(os.Getenv("PAPERBOAT_ENROLLED_GID"))
	for _, path := range []string{stateRoot, current, rollback, staged, cliCurrent, cliRollback, socket, tokenPath, controlSocket} {
		if !filepath.IsAbs(path) {
			return errors.New("invalid paperboat-updated environment")
		}
	}
	if repository == "" || machineID == "" || healthURL == "" || uidErr != nil || gidErr != nil || uid <= 0 || gid < 0 {
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
	service, err := updated.New(updated.Config{StateRoot: stateRoot, RuntimeCurrent: current, RuntimeRollback: rollback, RuntimeStaged: staged, CLICurrent: cliCurrent, CLIRollback: cliRollback, Active: active, WorkerUID: uid, WorkerGID: gid, SocketPath: socket, Token: token, RepositoryURL: repository, MachineID: machineID, Health: updated.HTTPHealth{Endpoint: healthURL}, ControlSocket: controlSocket})
	if err != nil {
		return err
	}
	if *now {
		_, err := service.UpdateNow(ctx)
		return err
	}
	return service.Run(ctx)
}
