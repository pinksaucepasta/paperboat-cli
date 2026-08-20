//go:build windows

package main

import "golang.org/x/sys/windows"

func splitDroppedPaths(value string) ([]string, error) { return windows.DecomposeCommandLine(value) }
