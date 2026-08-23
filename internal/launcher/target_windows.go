//go:build windows

package launcher

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

func resolveTargetPath(path string) (string, error) {
	activePath := filepath.Join(filepath.Dir(path), strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))+".active")
	if _, err := os.Lstat(activePath); errors.Is(err, os.ErrNotExist) {
		return path, nil
	} else if err != nil {
		return "", fmt.Errorf("%w: inspect active slot: %v", ErrUnsafeTarget, err)
	}
	if !validMachineFileSecurity(activePath, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)") {
		return "", fmt.Errorf("%w: active slot permissions are unsafe", ErrUnsafeTarget)
	}
	file, err := os.Open(activePath)
	if err != nil {
		return "", fmt.Errorf("%w: read active slot: %v", ErrUnsafeTarget, err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, 256))
	if !scanner.Scan() || scanner.Scan() || scanner.Err() != nil {
		return "", ErrUnsafeTarget
	}
	slot := scanner.Text()
	if len(slot) < 5 || len(slot) > 128 || !strings.HasPrefix(slot, strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))+".slot-") || !strings.HasSuffix(strings.ToLower(slot), ".exe") || strings.ContainsAny(slot, `/\:*?"<>|`) {
		return "", ErrUnsafeTarget
	}
	resolved := filepath.Join(filepath.Dir(path), slot)
	if filepath.Dir(resolved) != filepath.Dir(path) {
		return "", ErrUnsafeTarget
	}
	return resolved, nil
}

func validatePlatformTarget(path string, info fs.FileInfo) error {
	// The updater creates this fixed slot with a protected SYSTEM and
	// Administrators-only DACL. Reparse points were rejected by Lstat above.
	if !strings.EqualFold(filepath.Ext(info.Name()), ".exe") {
		return ErrUnsafeTarget
	}
	if !validMachineFileSecurity(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)") {
		return ErrUnsafeTarget
	}
	return nil
}

func validMachineFileSecurity(path, dacl string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	return err == nil && windowssecurity.OwnerMatchesSID(path, system) && windowssecurity.ProtectedDACLMatches(path, dacl)
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
