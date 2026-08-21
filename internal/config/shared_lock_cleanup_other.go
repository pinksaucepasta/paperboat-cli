//go:build !windows

package config

import "os"

func removeSharedLock(path string) error { return os.RemoveAll(path) }
