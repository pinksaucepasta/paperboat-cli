//go:build !windows

package main

import (
	"errors"

	"github.com/spf13/cobra"
)

// msiCleanupCommand is present in every build so the command tree remains
// cross-platform. The MSI custom action is Windows-only and can never be
// invoked successfully by a non-Windows build.
func msiCleanupCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "__msi-cleanup",
		Hidden:             true,
		DisableFlagParsing: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("__msi-cleanup is only available on Windows")
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}
