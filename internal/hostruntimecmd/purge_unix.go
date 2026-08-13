//go:build darwin || linux

package hostruntimecmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func runPurgeCommand(ctx context.Context, args []string, _ io.Reader, _, _ io.Writer) error {
	if len(args) != 0 {
		return errors.New("purge accepts no arguments")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "/usr/bin/sudo", "--", executable, "__runtime-service", "purge")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return errors.Join(err, errors.New(stderr.String()))
	}
	return nil
}

func purgeSystemInstallation(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("complete uninstall requires administrator approval")
	}
	if runtime.GOOS == "linux" {
		units := []string{"paperboat-runtime-host.service", "paperboat-runtime-privileged.service", "paperboat-helper.service", "paperboat-host-service.service", "paperboat-console.service"}
		for _, action := range []string{"stop", "disable"} {
			arguments := append([]string{action}, units...)
			_ = exec.CommandContext(ctx, "/usr/bin/systemctl", arguments...).Run()
		}
		for _, path := range []string{
			"/etc/systemd/system/paperboat-runtime-host.service", "/etc/systemd/system/paperboat-runtime-privileged.service",
			"/etc/systemd/system/paperboat-helper.service", "/etc/systemd/system/paperboat-helper.service.d",
			"/etc/systemd/system/paperboat-host-service.service",
			"/etc/systemd/system/paperboat-console.service",
		} {
			if err := os.RemoveAll(path); err != nil {
				return err
			}
		}
		_ = exec.CommandContext(ctx, "/usr/bin/systemctl", "daemon-reload").Run()
		arguments := append([]string{"reset-failed"}, units...)
		_ = exec.CommandContext(ctx, "/usr/bin/systemctl", arguments...).Run()
	}
	paths := []string{"/usr/local/libexec/paperboat", "/var/lib/paperboat-installer", "/var/lib/paperboat", "/var/run/paperboat", "/usr/local/bin/pb"}
	if runtime.GOOS == "darwin" {
		paths = []string{"/Library/PrivilegedHelperTools/Paperboat", "/Library/Application Support/Paperboat", "/var/run/paperboat", "/usr/local/bin/pb"}
	}
	var result error
	for _, path := range paths {
		result = errors.Join(result, os.RemoveAll(path))
	}
	return result
}
