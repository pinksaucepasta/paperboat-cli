//go:build windows

package session

import (
	"os"
)

// Windows has no SIGWINCH. Console resize notifications are handled by the
// ConPTY adapter, so there is no process signal to subscribe to here.
func notifyWinch(chan<- os.Signal) {}
