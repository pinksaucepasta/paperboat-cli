//go:build unix

package configsync

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

func restoreRegularFile(target string, content []byte, mode fs.FileMode) error {
	//paperboat:allow-source-policy atomic-replacement owner=config-sync reason=journal-restore-staging
	temporary, err := os.CreateTemp(filepath.Dir(target), ".paperboat-restore-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	err = temporary.Chmod(mode)
	if err == nil {
		_, err = temporary.Write(content)
	}
	if err == nil {
		err = temporary.Sync()
	}
	err = errors.Join(err, temporary.Close())
	if err != nil {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=config-sync reason=journaled-workspace-restore
	return os.Rename(temporaryPath, target)
}
