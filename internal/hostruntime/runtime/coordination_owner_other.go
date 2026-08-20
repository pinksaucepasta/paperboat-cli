//go:build !windows

package runtime

func stableHostOwnsCoordination() bool { return false }
