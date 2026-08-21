//go:build unix

package atomicfile

import "os"

// CurrentOwnerOptions returns the portable owner policy for files owned by
// the current process. Unix callers persist numeric UID/GID ownership;
// Windows callers use ACLs instead.
func CurrentOwnerOptions(mode os.FileMode) Options {
	return Options{Mode: mode, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid()}
}
