//go:build !windows

package main

import (
	"errors"

	"github.com/spf13/cobra"
)

func platformInstallCommand() *cobra.Command {
	return &cobra.Command{
		Use:           "__install",
		Hidden:        true,
		Args:          commandArgs(cobra.NoArgs),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(*cobra.Command, []string) error {
			return errors.New("__install is only supported on Windows")
		},
	}
}
