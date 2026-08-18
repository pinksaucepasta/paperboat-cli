//go:build darwin || linux

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func notifyResizeSignals(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGWINCH)
}
