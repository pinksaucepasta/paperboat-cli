//go:build windows

package main

// Windows does not support fsync on a directory handle opened through os.Open.
// The staged file itself is flushed before the same-volume atomic rename.
func syncDirectory(string) error {
	return nil
}
