//go:build !darwin && !linux

package managedssh

import "errors"

var ErrOpenSSHExecution = errors.New("OpenSSH execution is unsupported on this platform")

type ProcessExec func(path string, argv []string, envv []string) error
type OpenSSHExecutor struct{ Exec ProcessExec }

func (OpenSSHExecutor) Execute(string, []string, []string) error { return ErrOpenSSHExecution }
