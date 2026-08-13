//go:build darwin || linux

package localapi

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/adrg/xdg"
)

type Paths struct {
	StateRoot   string
	RuntimeRoot string
	SocketPath  string
	LockPath    string
}

func CurrentPaths(uid int) (Paths, error) {
	environ := func(name string) string {
		switch name {
		case "XDG_STATE_HOME":
			return xdg.StateHome
		case "XDG_RUNTIME_DIR":
			return xdg.RuntimeDir
		case "TMPDIR":
			return os.Getenv("TMPDIR")
		default:
			return ""
		}
	}
	return ResolvePaths(environ, xdg.Home, uid)
}

func ResolvePaths(environ func(string) string, home string, uid int) (Paths, error) {
	if environ == nil || !filepath.IsAbs(home) || uid < 0 {
		return Paths{}, ErrInvalidConfig
	}
	stateRoot, err := userStateRoot(environ, home)
	if err != nil {
		return Paths{}, err
	}
	if err := ensureOwnerDirectory(stateRoot, uid); err != nil {
		return Paths{}, err
	}
	runtimeBase := ""
	if runtime.GOOS == "linux" {
		if candidate := environ("XDG_RUNTIME_DIR"); candidate != "" {
			if !filepath.IsAbs(candidate) {
				return Paths{}, ErrInvalidConfig
			}
			if safeOwnerDirectory(candidate, uid) {
				runtimeBase = candidate
			}
		} else {
			candidate := filepath.Join("/run/user", strconv.Itoa(uid))
			if safeOwnerDirectory(candidate, uid) {
				runtimeBase = candidate
			}
		}
	} else {
		candidate := environ("TMPDIR")
		if candidate != "" && !filepath.IsAbs(candidate) {
			return Paths{}, ErrInvalidConfig
		}
		if candidate != "" && safeOwnerDirectory(candidate, uid) {
			runtimeBase = candidate
		}
	}
	var runtimeRoot string
	if runtimeBase == "" {
		runtimeRoot = filepath.Join(stateRoot, "run")
	} else {
		runtimeRoot = filepath.Join(runtimeBase, "paperboat")
	}
	if err := ensureOwnerDirectory(runtimeRoot, uid); err != nil {
		return Paths{}, err
	}
	result := Paths{StateRoot: stateRoot, RuntimeRoot: runtimeRoot, SocketPath: filepath.Join(runtimeRoot, "local-api.sock"), LockPath: filepath.Join(stateRoot, "daemon.lock")}
	if len(result.SocketPath) > maxUnixSocketPath {
		fallback := filepath.Join(stateRoot, "run")
		if err := ensureOwnerDirectory(fallback, uid); err != nil {
			return Paths{}, err
		}
		result.RuntimeRoot, result.SocketPath = fallback, filepath.Join(fallback, "local-api.sock")
	}
	if len(result.SocketPath) > maxUnixSocketPath {
		return Paths{}, ErrInvalidConfig
	}
	return result, nil
}

func userStateRoot(environ func(string) string, home string) (string, error) {
	if runtime.GOOS == "linux" {
		if base := environ("XDG_STATE_HOME"); base != "" {
			if !filepath.IsAbs(base) {
				return "", ErrInvalidConfig
			}
			return filepath.Join(filepath.Clean(base), "paperboat"), nil
		}
		return filepath.Join(home, ".local", "state", "paperboat"), nil
	}
	return filepath.Join(home, "Library", "Application Support", "Paperboat", "state"), nil
}

func ensureOwnerDirectory(path string, uid int) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalidConfig
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || fileOwner(info) != uid || info.Mode().Perm()&0o077 != 0 {
		if err != nil {
			return err
		}
		return ErrUnsafeSocket
	}
	return nil
}

func safeOwnerDirectory(path string, uid int) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && fileOwner(info) == uid && info.Mode().Perm()&0o022 == 0
}
