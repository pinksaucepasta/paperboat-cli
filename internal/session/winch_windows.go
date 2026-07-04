//go:build windows

package session

import "os"

// Windows has no SIGWINCH; resize propagation is handled at initial attach.
func notifyWinch(_ chan<- os.Signal) {}
