//go:build darwin || linux

package localapi

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func validateServerConfig(config ServerConfig) error {
	if !filepath.IsAbs(config.SocketPath) || len(config.SocketPath) > maxUnixSocketPath || config.OwnerUID < 0 || config.OwnerGID < 0 {
		return ErrInvalidConfig
	}
	return nil
}

func defaultReadAuthorizer(config ServerConfig) ReadAuthorizer {
	return func(peer Peer) bool { return peer.UID == config.OwnerUID }
}

func (s *Server) listen(ctx context.Context) (net.Listener, error) {
	directory := filepath.Dir(s.config.SocketPath)
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || fileOwner(info) != s.config.OwnerUID {
		return nil, ErrUnsafeSocket
	}
	if info, err := os.Lstat(s.config.SocketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 || fileOwner(info) != s.config.OwnerUID {
			return nil, ErrUnsafeSocket
		}
		connection, dialErr := net.DialTimeout("unix", s.config.SocketPath, 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return nil, ErrAlreadyRunning
		}
		if s.config.Stale == nil || !s.config.Stale.CanRemoveStaleSocket(ctx, s.config.SocketPath) {
			return nil, ErrUnsafeSocket
		}
		if err := removeVerifiedSocket(s.config.SocketPath, info, s.config.OwnerUID); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.config.SocketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(false)
	if os.Geteuid() == 0 {
		err = os.Chown(s.config.SocketPath, s.config.OwnerUID, s.config.OwnerGID)
	}
	if err == nil {
		err = os.Chmod(s.config.SocketPath, 0o600)
	}
	if err != nil {
		_ = listener.Close()
		_ = os.Remove(s.config.SocketPath)
		return nil, err
	}
	socketInfo, err := os.Lstat(s.config.SocketPath)
	if err != nil {
		_ = listener.Close()
		_ = os.Remove(s.config.SocketPath)
		return nil, err
	}
	s.cleanup = func() { _ = removeVerifiedSocket(s.config.SocketPath, socketInfo, s.config.OwnerUID) }
	return listener, nil
}

func removeVerifiedSocket(path string, expected os.FileInfo, ownerUID int) error {
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if expected == nil || current.Mode()&os.ModeSocket == 0 || current.Mode()&os.ModeSymlink != 0 || fileOwner(current) != ownerUID || !os.SameFile(expected, current) {
		return ErrUnsafeSocket
	}
	return os.Remove(path)
}

func fileOwner(info os.FileInfo) int {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Uid)
}
