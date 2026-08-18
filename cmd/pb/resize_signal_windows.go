//go:build windows

package main

import "os"

// Windows console resize notifications are delivered by the ConPTY adapter,
// not by a SIGWINCH process signal.
func notifyResizeSignals(chan<- os.Signal) {}
