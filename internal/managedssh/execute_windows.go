//go:build windows

package managedssh

import (
	"errors"
	"os"
	"os/exec"
	"strings"
)

var ErrOpenSSHExecution = errors.New("OpenSSH execution request is invalid")

type ProcessExec func(path string, argv []string, envv []string) error

type OpenSSHExecutor struct{ Exec ProcessExec }

// Execute runs the native OpenSSH client with inherited standard streams and
// returns its exact process error, including the native exit code.
func (e OpenSSHExecutor) Execute(executable string, arguments, environment []string) error {
	path, err := resolveOpenSSHExecutable(executable)
	if err != nil || !validProcessValues(arguments) || !validEnvironment(environment) {
		return ErrOpenSSHExecution
	}
	if e.Exec != nil {
		argv := append([]string{path}, arguments...)
		if environment == nil {
			environment = os.Environ()
		}
		return e.Exec(path, argv, append([]string(nil), environment...))
	}
	command := exec.Command(path, arguments...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	if environment != nil {
		command.Env = append([]string(nil), environment...)
	}
	return command.Run()
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
