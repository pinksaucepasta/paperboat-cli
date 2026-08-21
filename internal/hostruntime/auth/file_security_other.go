//go:build !unix && !windows

package auth

import "os"

func secureJWKSFile(_ string, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}
