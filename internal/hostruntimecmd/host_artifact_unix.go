//go:build darwin || linux

package hostruntimecmd

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
)

func VerifyHostArtifact(ctx context.Context, stateRoot string, artifact bootstrap.ArtifactTarget) error {
	if !filepath.IsAbs(stateRoot) {
		return errors.New("invalid Host artifact state root")
	}
	_, err := bootstrap.FetchVerifiedArtifact(ctx, artifact, filepath.Join(stateRoot, "tuf"), artifactHTTPClient())
	return err
}
