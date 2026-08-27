//go:build !darwin

package selfupdate

import "errors"

var errPackageInstall = errors.New("macOS package installation is unsupported on this platform")

func installDarwinPackage(string) error { return errPackageInstall }
