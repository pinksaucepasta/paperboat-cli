//go:build !windows

package supportbundle

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func validatePlatformOutputPath(outputPath string) error {
	parentFD, err := openOutputParent(outputPath)
	if err != nil {
		return &Error{Code: ErrorInvalidOutput, Operation: "write support bundle", Cause: err}
	}
	defer unix.Close(parentFD)

	var stat unix.Stat_t
	err = unix.Fstatat(parentFD, filepath.Base(outputPath), &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
			return &Error{Code: ErrorOutputSymlink, Operation: "write support bundle"}
		}
		return &Error{Code: ErrorOutputExists, Operation: "write support bundle"}
	}
	if !errors.Is(err, unix.ENOENT) {
		return &Error{Code: ErrorInvalidOutput, Operation: "write support bundle", Cause: err}
	}
	return nil
}

// openOutputParent walks from the filesystem root one component at a time.
// O_NOFOLLOW closes both the ancestor-symlink and parent-swap races, while the
// returned descriptor pins the verified directory for creation and publish.
func openOutputParent(outputPath string) (int, error) {
	parent := filepath.Dir(outputPath)
	current, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	components := strings.Split(strings.TrimPrefix(parent, string(filepath.Separator)), string(filepath.Separator))
	for _, component := range components {
		if component == "" {
			continue
		}
		next, openErr := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		closeErr := unix.Close(current)
		if openErr != nil {
			return -1, errors.Join(openErr, closeErr)
		}
		if closeErr != nil {
			unix.Close(next)
			return -1, closeErr
		}
		current = next
	}
	return current, nil
}

func (b *Builder) writeAtomic(ctx context.Context, outputPath string, body []byte) (err error) {
	parentFD, err := openOutputParent(outputPath)
	if err != nil {
		return &Error{Code: ErrorInvalidOutput, Operation: "create support bundle output", Cause: err}
	}
	defer unix.Close(parentFD)

	temporaryName, temporaryFD, err := createTemporaryAt(parentFD)
	if err != nil {
		return &Error{Code: ErrorWriteFailed, Operation: "create support bundle output", Cause: err}
	}
	temporaryPath := filepath.Join(filepath.Dir(outputPath), temporaryName)
	temporary := os.NewFile(uintptr(temporaryFD), temporaryPath)
	if temporary == nil {
		unix.Close(temporaryFD)
		unix.Unlinkat(parentFD, temporaryName, 0)
		return &Error{Code: ErrorWriteFailed, Operation: "create support bundle output"}
	}
	defer func() {
		if temporary != nil {
			_ = temporary.Close()
		}
		_ = unix.Unlinkat(parentFD, temporaryName, 0)
	}()

	if err := writeContext(ctx, temporary, body); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return &Error{Code: ErrorWriteFailed, Operation: "sync support bundle output", Cause: err}
	}
	if err := temporary.Close(); err != nil {
		return &Error{Code: ErrorWriteFailed, Operation: "close support bundle output", Cause: err}
	}
	temporary = nil
	if err := ctx.Err(); err != nil {
		return contextError("write support bundle", err)
	}
	if b.beforePublish != nil {
		if err := b.beforePublish(temporaryPath); err != nil {
			return &Error{Code: ErrorWriteFailed, Operation: "publish support bundle output", Cause: err}
		}
	}
	if err := ctx.Err(); err != nil {
		return contextError("write support bundle", err)
	}
	if err := unix.Linkat(parentFD, temporaryName, parentFD, filepath.Base(outputPath), 0); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return &Error{Code: ErrorOutputExists, Operation: "publish support bundle output", Cause: err}
		}
		return &Error{Code: ErrorWriteFailed, Operation: "publish support bundle output", Cause: err}
	}
	if err := unix.Unlinkat(parentFD, temporaryName, 0); err != nil {
		return &Error{Code: ErrorWriteFailed, Operation: "remove support bundle temporary output", Cause: err}
	}
	syncParent := func(string) error { return unix.Fsync(parentFD) }
	if b.syncParent != nil {
		syncParent = b.syncParent
	}
	if err := syncParent(filepath.Dir(outputPath)); err != nil {
		return &Error{Code: ErrorWriteFailed, Operation: "sync support bundle parent", Cause: err}
	}
	return nil
}

func createTemporaryAt(parentFD int) (string, int, error) {
	for attempt := 0; attempt < temporaryCreateAttempts; attempt++ {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return "", -1, err
		}
		name := ".paperboat-support-bundle-" + hex.EncodeToString(random)
		fd, err := unix.Openat(parentFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return name, fd, err
	}
	return "", -1, fs.ErrExist
}
