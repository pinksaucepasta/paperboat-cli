//go:build darwin || linux

package hostruntimecmd

import (
	"os"
	"os/user"
	"strconv"
)

// currentUnixUser resolves the account from the kernel UID instead of USER or
// LOGNAME. Release binaries use the pure-Go os/user implementation, whose
// Current result is environment-backed and can disagree with the real account
// name (for example, a macOS short name containing a dot).
func currentUnixUser() (*user.User, error) {
	return user.LookupId(strconv.Itoa(os.Getuid()))
}
