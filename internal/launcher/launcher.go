// Package launcher implements the stable pb entry point. Ordinary releases
// replace the fixed CLI slot, never this launcher.
package launcher

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
)

var ErrUnsafeTarget = errors.New("active Paperboat CLI is unsafe")

type Target struct {
	Path string
	Args []string
	Env  []string
}

func Resolve(args []string, environment []string) (Target, error) {
	layout, err := service.DefaultLayout(runtime.GOOS)
	if err != nil {
		return Target{}, err
	}
	path, err := resolveTargetPath(layout.CLICurrent)
	if err != nil {
		return Target{}, err
	}
	if err := validateTarget(path); err != nil {
		return Target{}, err
	}
	return Target{Path: path, Args: append([]string{"pb"}, args...), Env: append([]string(nil), environment...)}, nil
}

func validateTarget(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrUnsafeTarget
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafeTarget, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 512<<20 {
		return ErrUnsafeTarget
	}
	return validatePlatformTarget(path, info)
}
