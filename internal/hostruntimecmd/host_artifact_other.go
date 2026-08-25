//go:build !darwin && !linux && !windows

package hostruntimecmd

import (
	"context"
	"errors"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
)

func VerifyHostArtifact(context.Context, string, bootstrap.ArtifactTarget) error {
	return errors.New("Host artifact verification is unavailable on this platform")
}
