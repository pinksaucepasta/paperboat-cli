//go:build windows

package releaseeligibility

// Windows does not expose a portable directory fsync through os.File. The
// record itself is flushed before rename; the rename is the durable boundary
// available to this platform implementation.
func syncDirectory(string) error { return nil }
