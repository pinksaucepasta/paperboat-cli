//go:build !darwin && !linux

package managedssh

import "errors"

var ErrOpenSSHConfigConflict = errors.New("Paperboat OpenSSH configuration conflicts with existing state")

type OpenSSHConfig struct {
	Home, AliasSuffix, ProxyCommand, KnownHostsCommand, AgentSocket string
	OwnerUID                                                        uint32
}
type OpenSSHConfigResult struct{ Changed bool }

func InstallOpenSSHConfig(OpenSSHConfig) (OpenSSHConfigResult, error) {
	return OpenSSHConfigResult{}, errors.New("OpenSSH configuration is unsupported on this platform")
}
func ValidateOpenSSHConfig(OpenSSHConfig) error {
	return errors.New("OpenSSH configuration is unsupported on this platform")
}
func ValidateInstalledOpenSSHConfig(string, uint32, string, string) error {
	return errors.New("OpenSSH configuration is unsupported on this platform")
}
func UninstallOpenSSHConfig(string, uint32) (OpenSSHConfigResult, error) {
	return OpenSSHConfigResult{}, errors.New("OpenSSH configuration is unsupported on this platform")
}
