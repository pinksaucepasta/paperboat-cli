//go:build !windows

// Package processlaunch owns the operating-system process attributes used by
// Paperboat's non-interactive child processes.
package processlaunch

import "os/exec"

// ConfigureBackground is intentionally a no-op outside Windows. Unix service
// managers already detach their child processes without creating UI.
func ConfigureBackground(_ *exec.Cmd) {}
