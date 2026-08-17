//go:build windows

package workerupdate

import "os"

// Windows ownership is SID/DACL based, not POSIX-UID based. Until the Windows
// service adapter supplies a SID-aware storage verifier, this worker updater
// fails closed during configuration validation rather than pretending a UID
// check protects ProgramData.
func fileOwner(os.FileInfo) int { return -1 }
