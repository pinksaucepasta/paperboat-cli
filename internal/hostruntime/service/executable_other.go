//go:build !windows

package service

func safeExecutableWindows(path string) error { return safeExecutable(path) }
