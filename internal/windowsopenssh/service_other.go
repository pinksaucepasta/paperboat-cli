//go:build !windows

package windowsopenssh

import "context"

func InstallService(context.Context, string, string, string) error { return ErrInstallerUnavailable }
func RemoveServiceOwned(context.Context, Config) error             { return ErrInstallerUnavailable }
