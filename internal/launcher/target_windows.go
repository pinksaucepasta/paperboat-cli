//go:build windows

package launcher

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func validatePlatformTarget(path string, info fs.FileInfo) error {
	// The updater creates this fixed slot with a protected SYSTEM and
	// Administrators-only DACL. Reparse points were rejected by Lstat above.
	if !strings.EqualFold(filepath.Ext(info.Name()), ".exe") {
		return ErrUnsafeTarget
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrUnsafeTarget
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || !descriptor.IsValid() {
		return ErrUnsafeTarget
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || owner.String() != "S-1-5-18" {
		return ErrUnsafeTarget
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 || descriptor.String() != "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)" {
		return ErrUnsafeTarget
	}
	return nil
}

func Execute(target Target) error {
	if len(target.Args) == 0 || target.Path == "" {
		return ErrUnsafeTarget
	}
	command := exec.Command(target.Path, target.Args[1:]...)
	command.Env, command.Stdin, command.Stdout, command.Stderr = target.Env, os.Stdin, os.Stdout, os.Stderr
	err := command.Run()
	if exit, ok := err.(*exec.ExitError); ok {
		os.Exit(exit.ExitCode())
	}
	if err != nil {
		return fmt.Errorf("start active Paperboat CLI: %w", err)
	}
	return nil
}
