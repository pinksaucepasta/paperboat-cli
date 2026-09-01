//go:build !windows

package environmentmanager

import (
	"errors"
	"fmt"
	"os"
)

func syncMutationDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("sync ENV mutation state directory: %w", err)
	}
	return errors.Join(directory.Sync(), directory.Close())
}
