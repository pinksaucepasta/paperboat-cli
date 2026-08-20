//go:build unix

package inbox

import (
	"errors"
	"os"
)

func secureInboxPath(string) error { return nil }

func validateInboxPath(_ string, info os.FileInfo) error {
	if !ownedByCurrentUser(info) {
		return errors.New("inbox path must be owned by the current user")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("inbox path must not be writable by group or other users")
	}
	return nil
}
