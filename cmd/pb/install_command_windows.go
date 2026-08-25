//go:build windows

package main

import (
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/spf13/cobra"
)

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
			return hostinstall.InstallStandaloneBinary(command.Context(), source, version)
		},
	}
	command.Flags().String("source", "", "verified downloaded pb.exe")
	command.Flags().String("version", "", "release version")
	_ = command.MarkFlagRequired("source")
	_ = command.MarkFlagRequired("version")
	return command
}
