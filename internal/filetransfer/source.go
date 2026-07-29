package filetransfer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Limits struct {
	MaxFileBytes  int64
	MaxBatchFiles int
	MaxBatchBytes int64
}
type PreparedBatch struct {
	Sources []Source
	files   []*os.File
}

func (b *PreparedBatch) Close() error {
	var result error
	for _, file := range b.files {
		result = errors.Join(result, file.Close())
	}
	b.files = nil
	return result
}

func Prepare(paths []string, limits Limits) (*PreparedBatch, error) {
	if limits.MaxFileBytes <= 0 {
		limits.MaxFileBytes = 50 << 20
	}
	if limits.MaxBatchFiles <= 0 {
		limits.MaxBatchFiles = 10
	}
	if limits.MaxBatchBytes <= 0 {
		limits.MaxBatchBytes = 500 << 20
	}
	if len(paths) < 1 || len(paths) > limits.MaxBatchFiles {
		return nil, fmt.Errorf("file batch contains %d paths; limit is %d", len(paths), limits.MaxBatchFiles)
	}
	batch := &PreparedBatch{Sources: make([]Source, 0, len(paths))}
	failed := true
	defer func() {
		if failed {
			_ = batch.Close()
		}
	}()
	var total int64
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, fmt.Errorf("invalid absolute file path %q", path)
		}
		before, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("inspect file: %w", err)
		}
		if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file", path)
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open file: %w", err)
		}
		batch.files = append(batch.files, file)
		opened, err := file.Stat()
		if err != nil {
			return nil, fmt.Errorf("stat open file: %w", err)
		}
		if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
			return nil, fmt.Errorf("file changed while opening: %s", path)
		}
		if opened.Size() < 0 || opened.Size() > limits.MaxFileBytes {
			return nil, fmt.Errorf("file %s is %d bytes; limit is %d", path, opened.Size(), limits.MaxFileBytes)
		}
		total += opened.Size()
		if total > limits.MaxBatchBytes {
			return nil, fmt.Errorf("file batch is %d bytes; limit is %d", total, limits.MaxBatchBytes)
		}
		hash := sha256.New()
		read, err := io.CopyBuffer(hash, io.LimitReader(file, limits.MaxFileBytes+1), make([]byte, 32<<10))
		if err != nil {
			return nil, fmt.Errorf("hash file: %w", err)
		}
		if read != opened.Size() {
			return nil, fmt.Errorf("file changed while hashing: %s", path)
		}
		after, err := os.Lstat(path)
		if err != nil || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, after) {
			return nil, fmt.Errorf("file changed while hashing: %s", path)
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("rewind file: %w", err)
		}
		var digest [sha256.Size]byte
		copy(digest[:], hash.Sum(nil))
		batch.Sources = append(batch.Sources, Source{Basename: filepath.Base(path), Size: read, SHA256: digest, Reader: file})
	}
	failed = false
	return batch, nil
}

// PrepareDescriptors validates and hashes caller-owned descriptors without
// reopening their paths. Callers retain ownership of every file.
func PrepareDescriptors(paths []string, files []*os.File, limits Limits) ([]Source, error) {
	if len(paths) != len(files) || len(paths) == 0 {
		return nil, errors.New("file descriptors do not match paths")
	}
	if limits.MaxFileBytes <= 0 {
		limits.MaxFileBytes = 50 << 20
	}
	if limits.MaxBatchFiles <= 0 {
		limits.MaxBatchFiles = 10
	}
	if limits.MaxBatchBytes <= 0 {
		limits.MaxBatchBytes = 500 << 20
	}
	if len(paths) > limits.MaxBatchFiles {
		return nil, fmt.Errorf("file batch contains %d paths; limit is %d", len(paths), limits.MaxBatchFiles)
	}
	sources := make([]Source, 0, len(paths))
	var total int64
	for index, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || files[index] == nil {
			return nil, fmt.Errorf("invalid absolute file path %q", path)
		}
		pathInfo, err := os.Lstat(path)
		if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file", path)
		}
		opened, err := files[index].Stat()
		if err != nil || !opened.Mode().IsRegular() || !os.SameFile(pathInfo, opened) {
			return nil, fmt.Errorf("file changed while opening: %s", path)
		}
		if opened.Size() < 0 || opened.Size() > limits.MaxFileBytes {
			return nil, fmt.Errorf("file %s is %d bytes; limit is %d", path, opened.Size(), limits.MaxFileBytes)
		}
		total += opened.Size()
		if total > limits.MaxBatchBytes {
			return nil, fmt.Errorf("file batch is %d bytes; limit is %d", total, limits.MaxBatchBytes)
		}
		if _, err := files[index].Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		hash := sha256.New()
		read, err := io.CopyBuffer(hash, io.LimitReader(files[index], limits.MaxFileBytes+1), make([]byte, 32<<10))
		if err != nil || read != opened.Size() {
			return nil, fmt.Errorf("file changed while hashing: %s", path)
		}
		after, err := os.Lstat(path)
		if err != nil || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, after) {
			return nil, fmt.Errorf("file changed while hashing: %s", path)
		}
		if _, err := files[index].Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		var digest [sha256.Size]byte
		copy(digest[:], hash.Sum(nil))
		sources = append(sources, Source{Basename: filepath.Base(path), Size: read, SHA256: digest, Reader: files[index]})
	}
	return sources, nil
}

func NewBatchID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "fb_" + hex.EncodeToString(value[:]), nil
}
