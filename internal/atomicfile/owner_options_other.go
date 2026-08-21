//go:build !unix && !windows

package atomicfile

import "os"

func CurrentOwnerOptions(mode os.FileMode) Options {
	return Options{Mode: mode, OwnerUID: -1, OwnerGID: -1}
}
