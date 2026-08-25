//go:build darwin

package workerupdate

import (
	"context"
	"errors"
	"os/exec"
)

var errPackageInstall = errors.New("macOS package installation failed")

// installDarwinPackage is the only package installation boundary. The
// package has already passed TUF digest/length and native signature checks
// before this command is reached.
func installDarwinPackage(ctx context.Context, packagePath string) (string, error) {
	if packagePath == "" {
		return "", errPackageInstall
	}
	command := exec.CommandContext(ctx, "/usr/sbin/installer", "-pkg", packagePath, "-target", "/")
	if output, err := command.CombinedOutput(); err != nil {
		return "", errors.Join(errPackageInstall, errors.New(string(output)))
	}
	return "/usr/local/bin/pb", nil
}
