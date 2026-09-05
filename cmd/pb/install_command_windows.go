//go:build windows

package main

import (
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/spf13/cobra"
)

var installStandaloneBinaryWithFreshRecovery = hostinstall.InstallStandaloneBinaryWithFreshRecovery

func platformInstallCommand() *cobra.Command {
	command := &cobra.Command{
		Use:           "__install",
		Hidden:        true,
		Short:         "Install this verified Paperboat executable",
		Args:          commandArgs(cobra.NoArgs),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(command *cobra.Command, _ []string) error {
			source, err := command.Flags().GetString("source")
			if err != nil {
				return err
			}
			version, err := command.Flags().GetString("version")
			if err != nil {
				return err
			}
			fresh, err := command.Flags().GetBool("fresh")
			if err != nil {
				return err
			}
			if fresh {
				return installStandaloneBinaryWithFreshRecovery(command.Context(), source, version, true, recoverWindowsUninstall)
			}
			return hostinstall.InstallStandaloneBinary(command.Context(), source, version, false)
		},
	}
	command.Flags().String("source", "", "verified downloaded pb.exe")
	command.Flags().String("version", "", "release version")
	command.Flags().Bool("fresh", false, "remove an older Paperboat enrollment before installation")
	_ = command.MarkFlagRequired("source")
	_ = command.MarkFlagRequired("version")
	return command
}
