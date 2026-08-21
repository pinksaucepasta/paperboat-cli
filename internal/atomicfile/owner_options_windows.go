//go:build windows

package atomicfile

import "os"

// Windows has no POSIX UID/GID ownership. The Windows writer applies its
// protected current-user/SYSTEM/Administrators ACL instead.
func CurrentOwnerOptions(mode os.FileMode) Options {
	return Options{Mode: mode, OwnerUID: -1, OwnerGID: -1}
}
