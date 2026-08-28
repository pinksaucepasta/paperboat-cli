//go:build windows

package processlaunch

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

func TestConfigureBackgroundPreventsConsoleAndPreservesFlags(t *testing.T) {
	command := exec.Command("cmd.exe", "/c", "exit", "0")
	command.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	ConfigureBackground(command)
	want := uint32(windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP)
	if command.SysProcAttr.CreationFlags != want {
		t.Fatalf("creation flags=%#x want=%#x", command.SysProcAttr.CreationFlags, want)
	}
	if !command.SysProcAttr.HideWindow {
		t.Fatal("background child is allowed to display a window")
	}
}
