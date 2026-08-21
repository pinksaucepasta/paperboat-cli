//go:build !unix && !windows

package supervisorupdate

func prepareSupervisorUpdateTestRoot(string) error { return nil }
