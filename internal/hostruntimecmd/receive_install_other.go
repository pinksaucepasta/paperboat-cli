//go:build !darwin && !linux

package hostruntimecmd

import (
	"context"
	"errors"
	"io"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
)

type ReceiveInstallConfig struct {
	StateRoot, WorkspaceRoot, ControlURL, MachineID, ListenAddress string
	Artifact                                                       bootstrap.ArtifactTarget
}

func InstallReceive(context.Context, ReceiveInstallConfig, io.Reader, io.Writer, io.Writer) error {
	return errors.New("receive service installation is supported only on macOS and Linux")
}
