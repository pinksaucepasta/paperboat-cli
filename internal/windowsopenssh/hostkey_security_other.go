//go:build !windows

package windowsopenssh

func protectHostKeyFiles(...string) error           { return ErrInstallerUnavailable }
func protectHostPublicKeyFile(string, string) error { return ErrInstallerUnavailable }
