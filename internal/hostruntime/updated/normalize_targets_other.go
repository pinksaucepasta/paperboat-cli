//go:build !windows

package updated

// Windows transaction code is compiled on Unix for journal/transaction
// validation tests, but service-target normalization is Windows-specific.
func normalizeWindowsRollbackTargets(hostd, updater, ssh windowsServiceTarget) (windowsServiceTarget, windowsServiceTarget, windowsServiceTarget, error) {
	return hostd, updater, ssh, nil
}
