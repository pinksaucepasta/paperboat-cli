//go:build darwin || linux

package managedssh

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

var ErrOpenSSHExecution = errors.New("OpenSSH execution request is invalid")

type ProcessExec func(path string, argv []string, envv []string) error

type OpenSSHExecutor struct {
	Exec ProcessExec
}

// Execute replaces the current process with OpenSSH. A successful call never
// returns, which preserves OpenSSH's native stdio, TTY, signal, and exit status.
func (e OpenSSHExecutor) Execute(executable string, arguments, environment []string) error {
	path, err := resolveOpenSSHExecutable(executable)
	if err != nil || !validProcessValues(arguments) || !validEnvironment(environment) {
		return ErrOpenSSHExecution
	}
	execProcess := e.Exec
	if execProcess == nil {
		execProcess = syscall.Exec
	}
	argv := make([]string, 1, len(arguments)+1)
	argv[0] = path
	argv = append(argv, arguments...)
	if environment == nil {
		environment = os.Environ()
	}
	if err := execProcess(path, argv, append([]string(nil), environment...)); err != nil {
		return err
	}
	return ErrOpenSSHExecution
}

func resolveOpenSSHExecutable(value string) (string, error) {
	if value == "" {
		value = "ssh"
	}
	path, err := exec.LookPath(value)
	if err != nil {
		return "", err
	}
	path, err = filepath.Abs(path)
	if err != nil || filepath.Clean(path) != path {
		return "", ErrOpenSSHExecution
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", ErrOpenSSHExecution
	}
	return path, nil
}

func validProcessValues(values []string) bool {
	if len(values) == 0 || len(values) > 4096 {
		return false
	}
	for _, value := range values {
		if strings.ContainsRune(value, 0) || len(value) > 1<<20 {
			return false
		}
	}
	return true
}

func validEnvironment(values []string) bool {
	if values == nil {
		return true
	}
	if len(values) > 16384 {
		return false
	}
	for _, value := range values {
		name, _, ok := strings.Cut(value, "=")
		if !ok || name == "" || strings.ContainsAny(name, "\x00=") || strings.ContainsRune(value, 0) || len(value) > 1<<20 {
			return false
		}
	}
	return true
}
