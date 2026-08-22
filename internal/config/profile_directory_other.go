//go:build !windows

package config

import "os"

func ensureProfileDirectory(path string) error {
	return os.MkdirAll(path, 0o700)
}
