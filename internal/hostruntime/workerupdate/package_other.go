//go:build !darwin

package workerupdate

import (
	"context"
	"errors"
)

var errPackageInstall = errors.New("package installation is unsupported on this platform")

func installDarwinPackage(context.Context, string) (string, error) {
	return "", errPackageInstall
}
