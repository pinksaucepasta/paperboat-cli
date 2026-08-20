//go:build windows

package runtime

// Windows hostd currently fences a replaceable external worker process. Until
// coordination services have their own authenticated IPC surface, hostd must
// own them so production does not silently omit runtime observations, config
// sync, or hosted lifecycle work.
func stableHostOwnsCoordination() bool { return true }
