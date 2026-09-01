//go:build !windows

package main

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/pinksaucepasta/paperboat/internal/hostruntimecmd"
	"github.com/spf13/cobra"
)

func removePlatformProductInstallation(context.Context, []string, io.Writer) error {
	return nil
}

func platformUninstallSuccessMessage() string {
	return "Paperboat was completely removed. The Paperboat Inbox was preserved."
}

func platformProductHandoffRequired() bool { return false }

func platformRequiresConfirmedDaemonStop() bool { return false }

func unsafeCleanupPathTraversal(_ string, info os.FileInfo) (bool, error) {
	return info.Mode()&os.ModeSymlink != 0, nil
}

func purgePlatformRuntime(command *cobra.Command) error {
	if code := hostruntimecmd.Execute(command.Context(), []string{"purge"}, command.InOrStdin(), command.OutOrStdout(), command.ErrOrStderr()); code != 0 {
		return errors.New("runtime purge failed")
	}
	return nil
}

func platformUninstallHelperCommand() *cobra.Command {
	return &cobra.Command{Use: "__complete-uninstall", Hidden: true, RunE: func(*cobra.Command, []string) error {
		return errors.New("deferred uninstall is only available on Windows")
	}}
}
