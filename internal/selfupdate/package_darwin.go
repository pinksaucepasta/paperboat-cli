//go:build darwin

package selfupdate

import (
	"context"
	"errors"
	"os"
	"os/exec"
)

var errPackageInstall = errors.New("macOS package installation failed")

func installDarwinPackage(packagePath string) error {
	if packagePath == "" {
		return errPackageInstall
	}
	command := exec.CommandContext(context.Background(), "/usr/bin/sudo", "--", "/usr/sbin/installer", "-pkg", packagePath, "-target", "/")
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		return errors.Join(errPackageInstall, err)
	}
	return nil
}
