//go:build darwin || linux

package updated

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

type updaterExec func(string, []string, []string) error

// FixedUpdaterReexec replaces the running updater image without stopping its
// launchd or systemd job. The active worker remains alive, hostd keeps its
// workloads, and the updater immediately starts again from the committed
// binary at the same fixed path.
type FixedUpdaterReexec struct {
	binary string
	exec   updaterExec
}

func NewFixedUpdaterReexec(binary string) (*FixedUpdaterReexec, error) {
	if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		return nil, errors.New("invalid fixed updater executable")
	}
	info, err := os.Lstat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("invalid fixed updater executable")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return nil, errors.New("invalid fixed updater executable")
	}
	return &FixedUpdaterReexec{binary: binary, exec: syscall.Exec}, nil
}

func (r *FixedUpdaterReexec) Restart(ctx context.Context) error {
	if r == nil || r.exec == nil || !filepath.IsAbs(r.binary) || filepath.Clean(r.binary) != r.binary {
		return errors.New("invalid fixed updater reexec")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return r.exec(r.binary, []string{r.binary, "__runtime-updated"}, os.Environ())
}
