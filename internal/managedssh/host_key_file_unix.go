//go:build darwin || linux

package managedssh

import (
	"os"

	"golang.org/x/sys/unix"
)

func openOwnedPublicFile(path string, ownerUID uint32) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != ownerUID || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o022 != 0 {
		_ = unix.Close(fd)
		return nil, ErrHostKeyInventory
	}
	return os.NewFile(uintptr(fd), path), nil
}
