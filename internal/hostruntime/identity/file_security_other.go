//go:build !darwin && !linux && !windows

package identity

import "os"

func secureIdentityFile(_ string, info os.FileInfo, _ bool) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}

func secureIdentityPath(_ string, info os.FileInfo, requirePrivateMode bool) bool {
	return secureIdentityFile("", info, requirePrivateMode)
}
