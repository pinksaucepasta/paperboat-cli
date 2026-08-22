//go:build !windows

package managedssh

import (
	"context"
	"os/exec"
)

func runOpenSSHProbeCommand(_ context.Context, command *exec.Cmd) error {
	return command.Run()
}

func openSSHProbeKnownHostsCommand() string {
	return "none"
}
