//go:build !windows

package main

import (
	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/command"
	"github.com/pinksaucepasta/paperboat/internal/managedssh"
	"github.com/spf13/cobra"
)

func executeManagedSSH(_ *cobra.Command, _ *command.Context, _ api.UserMachine, destination managedssh.Destination, passthrough []string, includePassthrough bool, environment []string) error {
	return (managedssh.OpenSSHExecutor{}).Execute("ssh", openSSHArguments(destination, passthrough, includePassthrough), environment)
}
