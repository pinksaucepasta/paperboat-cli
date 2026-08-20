//go:build !windows

package windowsopenssh

func protectHostKeyFiles(...string) error { return ErrInstallerUnavailable }
