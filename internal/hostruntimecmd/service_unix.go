//go:build darwin || linux

package hostruntimecmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
)

func runServiceCommand(ctx context.Context, args []string, stdin io.Reader, _, _ io.Writer) error {
	if len(args) != 1 || args[0] != "install" && args[0] != "commit" && args[0] != "uninstall" && args[0] != "uninstall-persisted" && args[0] != "purge" {
		return errors.New("service requires install, commit, or uninstall")
	}
	if args[0] == "uninstall" && os.Geteuid() != 0 {
		if _, err := os.Stat(systemWorkerExecutable()); errors.Is(err, os.ErrNotExist) {
			return removeSystemWorkerCommand()
		} else if err != nil {
			return err
		}
		if err := authorizePersistedUninstall(ctx); err != nil {
			return err
		}
		return removeSystemWorkerCommand()
	}
	if os.Geteuid() != 0 {
		return hostinstall.ErrNotPrivileged
	}
	if args[0] == "uninstall-persisted" {
		return hostinstall.UninstallPersisted(ctx)
	}
	if args[0] == "purge" {
		return purgeSystemInstallation(ctx)
	}
	request, err := hostinstall.Decode(stdin)
	if err != nil {
		return err
	}
	if args[0] == "uninstall" {
		return hostinstall.Uninstall(ctx, request)
	}
	if args[0] == "commit" {
		return hostinstall.Commit(request)
	}
	return hostinstall.Install(ctx, request)
}

func authorizePersistedUninstall(ctx context.Context) error {
	executable := systemWorkerExecutable()
	command := exec.CommandContext(ctx, "/usr/bin/sudo", "--", executable, "__runtime-service", "uninstall-persisted")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("administrator approval or service removal failed: %w: %s", err, stderr.String())
	}
	return nil
}

func systemWorkerExecutable() string {
	if runtime.GOOS == "darwin" {
		return "/Library/PrivilegedHelperTools/Paperboat/pb"
	}
	return "/usr/local/libexec/paperboat/pb"
}

func removeSystemWorkerCommand() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	commandPath := filepath.Join(home, ".local", "bin", "pb")
	info, err := os.Lstat(commandPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return nil
	}
	target, err := os.Readlink(commandPath)
	if err != nil {
		return err
	}
	if target != systemWorkerExecutable() {
		return nil
	}
	return os.Remove(commandPath)
}
