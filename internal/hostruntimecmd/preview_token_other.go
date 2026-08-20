//go:build !windows

package hostruntimecmd

import (
	"errors"
	"os"
)

func readPreviewAuthorizationToken(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() > 4096 {
		return nil, errors.New("local host-runtime preview authorization is unavailable")
	}
	return os.ReadFile(path)
}
