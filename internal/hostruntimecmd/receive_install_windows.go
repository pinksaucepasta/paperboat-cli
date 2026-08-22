//go:build windows

package hostruntimecmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/windows/elevation"
)

type ReceiveInstallConfig struct {
	StateRoot, WorkspaceRoot, ControlURL, MachineID, ListenAddress string
	Artifact                                                       bootstrap.ArtifactTarget
}

// InstallReceive shares the same verified artifact, slots, service contract,
// and rollback behavior as bootstrap. No receive-only Windows service exists.
func InstallReceive(ctx context.Context, config ReceiveInstallConfig, _ io.Reader, stdout, _ io.Writer) error {
	if !filepath.IsAbs(config.StateRoot) || !filepath.IsAbs(config.WorkspaceRoot) || config.MachineID == "" {
		return errors.New("invalid Windows receive installation")
	}
	artifactPath, err := bootstrap.FetchVerifiedArtifact(ctx, config.Artifact, filepath.Join(config.StateRoot, "tuf"), windowsArtifactHTTPClient())
	if err != nil {
		return err
	}
	account, err := user.Current()
	if err != nil {
		return err
	}
	sid, err := currentBootstrapSID()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	request := hostinstall.Request{Schema: hostinstall.SchemaV1, Platform: runtime.GOOS, User: windowsAccountName(account.Username), Group: "Paperboat", OwnerSID: sid, Executable: artifactPath, Artifact: config.Artifact, Home: home, Path: os.Getenv("PATH"), StateRoot: config.StateRoot, WorkspaceRoot: config.WorkspaceRoot, ControlURL: config.ControlURL, UserMachineID: config.MachineID, Shell: filepath.Join(os.Getenv("WINDIR"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), HelperListenAddress: config.ListenAddress, SetupMode: "client"}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if err := elevation.RunRuntimeService(ctx, executable, elevation.ActionInstallCommit, request); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Paperboat Windows receive service is ready.")
	return nil
}
