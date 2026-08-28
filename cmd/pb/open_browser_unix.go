//go:build !windows

package main

import (
	"os/exec"
	"runtime"
)

func platformOpenBrowser(target string) error {
	if runtime.GOOS == "darwin" {
		return exec.Command("open", target).Start()
	}
	return exec.Command("xdg-open", target).Start()
}
