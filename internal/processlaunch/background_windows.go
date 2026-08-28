//go:build windows

// Package processlaunch owns the operating-system process attributes used by
// Paperboat's non-interactive child processes.
package processlaunch

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// ConfigureBackground prevents a non-interactive Windows child from
// allocating or displaying a console window. Existing creation flags are
// preserved so callers can still request suspension or job-safe grouping.
func ConfigureBackground(command *exec.Cmd) {
	if command == nil {
		return
	}
	if command.SysProcAttr == nil {
		command.SysProcAttr = &syscall.SysProcAttr{}
	}
	command.SysProcAttr.CreationFlags |= windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP
	command.SysProcAttr.HideWindow = true
}
