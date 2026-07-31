//go:build !darwin && !linux

package inbox

import "os"

func ownedByCurrentUser(os.FileInfo) bool { return true }
