//go:build darwin || linux

package managedssh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func ListenOwnerSocket(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("managed SSH agent socket path must be absolute")
	}
	parent := filepath.Dir(filepath.Clean(path))
	info, err := os.Lstat(parent)
	if err != nil {
		return nil, fmt.Errorf("inspect managed SSH runtime directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0o700 || stat.Uid != uint32(os.Getuid()) {
		return nil, errors.New("managed SSH runtime directory must be owner-controlled mode 0700")
	}
	if socketInfo, err := os.Lstat(path); err == nil {
		stat, ok := socketInfo.Sys().(*syscall.Stat_t)
		if !ok || socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode().Perm() != 0o600 || stat.Uid != uint32(os.Getuid()) {
			return nil, errors.New("managed SSH agent socket path already exists")
		}
		connection, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return nil, errors.New("managed SSH agent socket path already exists")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("probe managed SSH agent socket: %w", dialErr)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale managed SSH agent socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect managed SSH agent socket: %w", err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("protect managed SSH agent socket: %w", err)
	}
	return &ownedUnixListener{UnixListener: listener, path: path}, nil
}

type ownedUnixListener struct {
	*net.UnixListener
	path string
}

func (l *ownedUnixListener) Close() error {
	err := l.UnixListener.Close()
	removeErr := os.Remove(l.path)
	if os.IsNotExist(removeErr) {
		removeErr = nil
	}
	return errors.Join(err, removeErr)
}
