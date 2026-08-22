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
		identity, err := socketIdentityFromInfo(info)
		if err != nil {
			return nil, ErrUnsafeSocket
		}
		if err := removeVerifiedSocket(s.config.SocketPath, identity, s.config.OwnerUID); err != nil {
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
	identity, err := socketIdentityFromListener(listener, s.config.SocketPath, os.Geteuid())
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	removeOwnSocket := func() { _ = removeVerifiedSocket(s.config.SocketPath, identity, s.config.OwnerUID) }
	if os.Geteuid() == 0 {
		err = os.Chown(s.config.SocketPath, s.config.OwnerUID, s.config.OwnerGID)
	}
	if err == nil {
		err = os.Chmod(s.config.SocketPath, 0o600)
	}
	if err != nil {
		_ = listener.Close()
		removeOwnSocket()
		return nil, err
	}
	if err := verifySocketIdentity(s.config.SocketPath, identity, s.config.OwnerUID); err != nil {
		_ = listener.Close()
		removeOwnSocket()
		return nil, err
	}
	s.cleanup = removeOwnSocket
	return listener, nil
}

type socketIdentity struct {
	device uint64
	inode  uint64
}

func socketIdentityFromInfo(info os.FileInfo) (socketIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return socketIdentity{}, ErrUnsafeSocket
	}
	return socketIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func socketIdentityFromListener(listener *net.UnixListener, path string, ownerUID int) (socketIdentity, error) {
	raw, err := listener.SyscallConn()
	if err != nil {
		return socketIdentity{}, err
	}
	var stat syscall.Stat_t
	var controlErr error
	if err := raw.Control(func(fd uintptr) { controlErr = syscall.Fstat(int(fd), &stat) }); err != nil {
		return socketIdentity{}, err
	}
	if controlErr != nil {
		return socketIdentity{}, controlErr
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		return socketIdentity{}, ErrUnsafeSocket
	}
	// Darwin's socket descriptor identity is not the filesystem vnode identity.
	// Use Fstat to prove the listener itself is a socket, then capture the pathname
	// vnode that all later cleanup must match exactly.
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 || fileOwner(info) != ownerUID {
		return socketIdentity{}, ErrUnsafeSocket
	}
	return socketIdentityFromInfo(info)
}

func verifySocketIdentity(path string, expected socketIdentity, ownerUID int) error {
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ErrUnsafeSocket
	}
	if err != nil {
		return err
	}
	actual, err := socketIdentityFromInfo(current)
	if err != nil || current.Mode()&os.ModeSocket == 0 || current.Mode()&os.ModeSymlink != 0 || fileOwner(current) != ownerUID || actual != expected {
		return ErrUnsafeSocket
	}
	return nil
}

func removeVerifiedSocket(path string, expected socketIdentity, ownerUID int) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := verifySocketIdentity(path, expected, ownerUID); err != nil {
		return err
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
