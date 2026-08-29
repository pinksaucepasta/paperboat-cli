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
	active, err := resolveUpdatedActive(ctx, filepath.Join(stateRoot, "transaction.json"), buildinfo.Version, source.Active)
	if err != nil {
		return err
	}
	updaterService, err := updated.New(updated.Config{StateRoot: stateRoot, Binary: binary, BinaryRollback: binaryRollback, BinaryStaged: binaryStaged, Active: active, WorkerUID: uid, WorkerGID: gid, SocketPath: socket, Token: token, RepositoryURL: repository, MachineID: machineID, Health: updated.HTTPHealth{Endpoint: healthURL}, ControlSocket: controlSocket, Restarter: updated.FixedUpdaterRestarter{Platform: runtime.GOOS, Runner: service.ExecRunner{}}})
	if err != nil {
		return err
	}
	if *now {
		_, err := updaterService.UpdateNow(ctx)
		return err
	}
	return updaterService.Run(ctx)
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
