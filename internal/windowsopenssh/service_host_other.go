//go:build !windows

package windowsopenssh

func RunServiceHost(string, string) error { return ErrInstallerUnavailable }
