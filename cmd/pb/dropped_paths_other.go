//go:build !unix && !windows

package main

import shlex "github.com/anmitsu/go-shlex"

func splitDroppedPaths(value string) ([]string, error) { return shlex.Split(value, true) }
