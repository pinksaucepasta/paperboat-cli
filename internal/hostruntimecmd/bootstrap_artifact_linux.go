//go:build linux

package hostruntimecmd

import "context"

func materializeUnixBootstrapArtifact(_ context.Context, path string) (string, error) {
	return path, nil
}
