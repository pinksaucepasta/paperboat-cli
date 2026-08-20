//go:build !unix && !windows

package configsync

import (
	"io/fs"
	"os"
)

func restoreRegularFile(target string, content []byte, mode fs.FileMode) error {
	return os.WriteFile(target, content, mode)
}
