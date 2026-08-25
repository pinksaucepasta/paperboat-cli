//go:build darwin || linux

package runtime

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

func writePeerLastError(stateRoot string, body []byte) error {
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot {
		return ErrProductionInvalid
	}
	path := filepath.Join(stateRoot, "runtime", "peer-last-error.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := atomicfile.Write(path, body, atomicfile.Options{Mode: 0o600, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid()}); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrProductionInvalid, err)
	}
	return nil
}
