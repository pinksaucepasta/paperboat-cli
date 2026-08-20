//go:build !windows

package telemetry

import (
	"io/fs"
)

func secureTelemetryFile(string) error { return nil }

func telemetryFilePrivate(_ string, info fs.FileInfo) bool {
	return info != nil && info.Mode().Perm() == 0o600
}
