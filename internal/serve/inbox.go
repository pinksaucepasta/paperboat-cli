package serve

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxInboxNameAttempts = 1000

var ErrInboxCollision = errors.New("no collision-free serve Inbox name available")

type InboxCopy struct {
	Path   string
	Size   int64
	SHA256 [sha256.Size]byte
}

func PlanInboxCopy(source Source, inboxPath string) (string, error) {
	if source.Kind != SourceFile || !filepath.IsAbs(inboxPath) {
		return "", ErrInvalidSource
	}
	if err := source.Revalidate(); err != nil {
		return "", err
	}
	return availableInboxPath(filepath.Join(filepath.Clean(inboxPath), "serve"), filepath.Base(source.Path))
}

func CopyFileToInbox(ctx context.Context, source Source, inboxPath string) (result InboxCopy, returnErr error) {
	return copyFileToInbox(ctx, source, inboxPath, hashFile)
}

func copyFileToInbox(ctx context.Context, source Source, inboxPath string, verify func(string) (int64, [sha256.Size]byte, error)) (result InboxCopy, returnErr error) {
	if ctx == nil || source.Kind != SourceFile || !filepath.IsAbs(inboxPath) {
		return InboxCopy{}, ErrInvalidSource
	}
	if verify == nil {
		return InboxCopy{}, ErrInvalidSource
	}
	if err := source.Revalidate(); err != nil {
		return InboxCopy{}, err
	}
	directory := filepath.Join(filepath.Clean(inboxPath), "serve")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return InboxCopy{}, fmt.Errorf("create serve Inbox: %w", err)
	}
	input, err := os.Open(source.Path)
	if err != nil {
		return InboxCopy{}, fmt.Errorf("open serve source: %w", err)
	}
	defer input.Close()
	openedInfo, err := input.Stat()
	if err != nil || !os.SameFile(source.info, openedInfo) {
		return InboxCopy{}, errors.Join(ErrSourceChanged, err)
	}
	temporary, err := os.CreateTemp(directory, ".copy-*")
	if err != nil {
		return InboxCopy{}, fmt.Errorf("create serve Inbox temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(openedInfo.Mode().Perm() & 0o666); err != nil {
		return InboxCopy{}, err
	}
	hash := sha256.New()
	written, err := copyContext(ctx, io.MultiWriter(temporary, hash), input)
	if err != nil {
		return InboxCopy{}, fmt.Errorf("copy serve Inbox file: %w", err)
	}
	if written != openedInfo.Size() || source.Revalidate() != nil {
		return InboxCopy{}, ErrSourceChanged
	}
	if err := temporary.Sync(); err != nil {
		return InboxCopy{}, fmt.Errorf("sync serve Inbox file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return InboxCopy{}, fmt.Errorf("close serve Inbox file: %w", err)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	verifiedSize, verifiedHash, err := verify(temporaryPath)
	if err != nil || verifiedSize != written || verifiedHash != digest {
		return InboxCopy{}, fmt.Errorf("verify serve Inbox file: %w", errors.Join(ErrSourceChanged, err))
	}
	finalPath, err := publishInboxFile(temporaryPath, directory, filepath.Base(source.Path))
	if err != nil {
		return InboxCopy{}, err
	}
	result = InboxCopy{Path: finalPath, Size: written, SHA256: digest}
	defer func() {
		if returnErr != nil {
			_ = os.Remove(finalPath)
			_ = syncDirectory(directory)
		}
	}()
	if err := syncDirectory(directory); err != nil {
		return InboxCopy{}, fmt.Errorf("sync serve Inbox directory: %w", err)
	}
	return result, nil
}

func copyContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 128*1024)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			count, writeErr := destination.Write(buffer[:read])
			written += int64(count)
			if writeErr != nil {
				return written, writeErr
			}
			if count != read {
				return written, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return written, nil
		}
		if readErr != nil {
			return written, readErr
		}
	}
}

func publishInboxFile(temporaryPath, directory, originalName string) (string, error) {
	for attempt := 0; attempt < maxInboxNameAttempts; attempt++ {
		finalPath := inboxAttemptPath(directory, originalName, attempt)
		if err := os.Link(temporaryPath, finalPath); err == nil {
			if err := os.Remove(temporaryPath); err != nil {
				_ = os.Remove(finalPath)
				return "", err
			}
			return finalPath, nil
		} else if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("publish serve Inbox file: %w", err)
		}
	}
	return "", ErrInboxCollision
}

func availableInboxPath(directory, originalName string) (string, error) {
	for attempt := 0; attempt < maxInboxNameAttempts; attempt++ {
		candidate := inboxAttemptPath(directory, originalName, attempt)
		if _, err := os.Lstat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", ErrInboxCollision
}

func inboxAttemptPath(directory, originalName string, attempt int) string {
	extension := filepath.Ext(originalName)
	stem := strings.TrimSuffix(originalName, extension)
	name := originalName
	if attempt > 0 {
		name = fmt.Sprintf("%s-%d%s", stem, attempt, extension)
	}
	return filepath.Join(directory, name)
}

func hashFile(name string) (int64, [sha256.Size]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return 0, [sha256.Size]byte{}, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return size, digest, err
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
