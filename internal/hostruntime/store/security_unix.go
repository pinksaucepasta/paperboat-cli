//go:build !windows

package store

import "os"

func secureStoreDirectory(path string) error { return os.Chmod(path, 0o700) }
func secureStoreFile(path string) error      { return os.Chmod(path, 0o600) }
