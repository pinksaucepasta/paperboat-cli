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
	file, err := os.Open(activePath)
	if errors.Is(err, os.ErrNotExist) {
		return path, nil
	}
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
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrUnsafeTarget
	}
	if !windowssecurity.ProtectedDACLMatches(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)") {
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
