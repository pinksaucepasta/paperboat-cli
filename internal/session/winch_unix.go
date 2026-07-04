//go:build !windows

package session

import (
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

func notifyWinch(ch chan<- os.Signal) {
	signal.Notify(ch, unix.SIGWINCH)
}
