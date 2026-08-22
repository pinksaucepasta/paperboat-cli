//go:build !darwin && !linux && !windows

package hostruntimecmd

import (
	"context"
	"errors"
	"io"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
)

type ClientInstallConfig struct {
	StateRoot, WorkspaceRoot, ControlURL, MachineID, ListenAddress string
	Artifact                                                       bootstrap.ArtifactTarget
}

func InstallClient(context.Context, ClientInstallConfig, io.Reader, io.Writer, io.Writer) error {
	return errors.New("Client service installation is supported only on macOS, Linux, and Windows")
}
