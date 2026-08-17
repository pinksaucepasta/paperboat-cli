//go:build darwin || linux

package launcher

import (
	"fmt"
	"io/fs"
	"syscall"
)

func validatePlatformTarget(_ string, info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o100 == 0 {
		return ErrUnsafeTarget
	}
	return nil
}

func Execute(target Target) error {
	if len(target.Args) == 0 || target.Path == "" {
		return ErrUnsafeTarget
	}
	if err := syscall.Exec(target.Path, target.Args, target.Env); err != nil {
		return fmt.Errorf("start active Paperboat CLI: %w", err)
	}
	return nil
}
